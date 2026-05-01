use crate::settings::{SchedulerHint, Settings};
use std::{collections::HashMap, hash::Hash, mem};

const WFQ_TAG_SCALE: u64 = 256;
const MAX_EXPLICIT_GROUPS: usize = 16;
const FALLBACK_GROUP_BUCKET: u64 = u64::MAX;
const SYNTHETIC_STREAM_KEY_BIT: u64 = 1 << 63;
const MAX_SIGNED_I64: i64 = i64::MAX;

const INTERACTIVE_BURST_LIMIT: u32 = 8;
const BULK_RESERVE_WINDOW: u32 = 4;
const BULK_ENTRY_MULTIPLIER: u64 = 2;
const AGING_ROUND_THRESHOLD: usize = 2;
const CLASS_SCORE_SCALE: u64 = 8;
const DEFAULT_WRITE_BURST_FRAMES: u32 = 16;
const MILD_WRITE_BURST_FRAMES: u32 = 8;
const STRONG_WRITE_BURST_FRAMES: u32 = 4;
const SATURATED_WRITE_BURST_FRAMES: u32 = 2;
const GROUP_STREAM_INDEX_THRESHOLD: usize = 8;
const BATCH_SCRATCH_RETAIN_FACTOR: usize = 4;
const MIN_BATCH_SCRATCH_RETAIN_HINT: usize = 256;
const STREAM_QUEUE_COMPACT_HEAD_MIN: usize = 32;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(super) struct GroupKey {
    kind: u8,
    value: u64,
}

impl GroupKey {
    pub(super) fn stream(stream_id: u64) -> Self {
        Self {
            kind: 0,
            value: stream_id,
        }
    }

    pub(super) fn explicit(group_id: u64) -> Self {
        Self {
            kind: 1,
            value: group_id,
        }
    }

    pub(super) fn transient(index: usize) -> Self {
        Self {
            kind: 2,
            value: usize_to_u64_saturating(index),
        }
    }

    fn is_transient(self) -> bool {
        self.kind == 2
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RequestMeta {
    pub(super) group_key: GroupKey,
    pub(super) stream_id: u64,
    pub(super) stream_scoped: bool,
    pub(super) is_priority_update: bool,
    pub(super) cost: i64,
    pub(super) urgency_rank: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct StreamMeta {
    pub(super) priority: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct BatchItem {
    pub(super) request: RequestMeta,
    pub(super) stream: StreamMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BatchConfig {
    pub(super) urgent: bool,
    pub(super) scheduler_hint: SchedulerHint,
    pub(super) max_frame_payload: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            urgent: false,
            scheduler_hint: SchedulerHint::UnspecifiedOrBalanced,
            max_frame_payload: Settings::default().max_frame_payload,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficClass {
    Interactive,
    Bulk,
}

#[derive(Debug, Default)]
pub(super) struct BatchScheduler {
    state: BatchState,
    active_group_refs: HashMap<u64, u64>,
    stream_group_buckets: HashMap<u64, u64>,
    stream_group_values: HashMap<u64, u64>,
}

impl BatchScheduler {
    pub(super) fn clear(&mut self) {
        *self = Self::default();
    }

    #[cfg(test)]
    pub(super) fn order(&mut self, cfg: BatchConfig, items: &[BatchItem]) -> Vec<usize> {
        let mut out = Vec::new();
        self.order_into(cfg, items, &mut out);
        out
    }

    pub(super) fn order_into(
        &mut self,
        cfg: BatchConfig,
        items: &[BatchItem],
        out: &mut Vec<usize>,
    ) {
        order_batch_indices_into(cfg, &mut self.state, items, out);
    }

    pub(super) fn group_key_for_stream(
        &mut self,
        stream_id: u64,
        group: Option<u64>,
        group_fair: bool,
    ) -> GroupKey {
        let group = group.unwrap_or(0);
        if stream_id == 0 || !group_fair || group == 0 {
            self.set_stream_group_bucket(stream_id, 0, 0);
            return GroupKey::stream(stream_id);
        }

        if self.stream_group_values.get(&stream_id).copied() == Some(group) {
            if let Some(bucket) = self.stream_group_buckets.get(&stream_id).copied() {
                if bucket != 0 {
                    return GroupKey::explicit(bucket);
                }
            }
        }

        let bucket = if self.active_group_refs.contains_key(&group)
            || self.tracked_explicit_group_count() < MAX_EXPLICIT_GROUPS
        {
            group
        } else {
            FALLBACK_GROUP_BUCKET
        };
        self.set_stream_group_bucket(stream_id, group, bucket);
        GroupKey::explicit(bucket)
    }

    pub(super) fn drop_stream(&mut self, stream_id: u64) {
        if stream_id == 0 {
            return;
        }
        self.untrack_stream_group(stream_id);
        self.state.stream_finish_tag.remove(&stream_id);
        self.state.stream_last_service.remove(&stream_id);
        self.state.stream_lag.remove(&stream_id);
        self.state.stream_class.remove(&stream_id);
        self.state.stream_last_seen_batch.remove(&stream_id);
        self.state.small_burst_disarmed.remove(&stream_id);
        self.drop_group_state(GroupKey::stream(stream_id));
        self.maybe_clear_idle_state();
    }

    fn set_stream_group_bucket(&mut self, stream_id: u64, group: u64, bucket: u64) {
        if stream_id == 0 {
            return;
        }
        let old_bucket = self
            .stream_group_buckets
            .get(&stream_id)
            .copied()
            .unwrap_or(0);
        let old_group = self
            .stream_group_values
            .get(&stream_id)
            .copied()
            .unwrap_or(0);
        if old_group == group && old_bucket == bucket {
            return;
        }
        self.untrack_stream_group(stream_id);
        if bucket == 0 {
            self.stream_group_values.remove(&stream_id);
            self.stream_group_buckets.remove(&stream_id);
            return;
        }
        let refs = self.active_group_refs.entry(bucket).or_default();
        *refs = refs.saturating_add(1);
        self.stream_group_values.insert(stream_id, group);
        self.stream_group_buckets.insert(stream_id, bucket);
        self.drop_group_state(GroupKey::stream(stream_id));
    }

    fn untrack_stream_group(&mut self, stream_id: u64) {
        let Some(bucket) = self.stream_group_buckets.remove(&stream_id) else {
            self.stream_group_values.remove(&stream_id);
            return;
        };
        self.stream_group_values.remove(&stream_id);
        if bucket == 0 {
            return;
        }
        match self.active_group_refs.get_mut(&bucket) {
            Some(refs) if *refs > 1 => *refs -= 1,
            Some(_) => {
                self.active_group_refs.remove(&bucket);
                self.drop_group_state(GroupKey::explicit(bucket));
            }
            None => {}
        }
    }

    fn tracked_explicit_group_count(&self) -> usize {
        self.active_group_refs
            .keys()
            .filter(|group| **group != 0 && **group != FALLBACK_GROUP_BUCKET)
            .count()
    }

    fn drop_group_state(&mut self, group: GroupKey) {
        self.state.group_virtual_time.remove(&group);
        self.state.group_finish_tag.remove(&group);
        self.state.group_last_service.remove(&group);
        self.state.group_lag.remove(&group);
        self.state.preferred_stream_head.remove(&group);
        if self.state.preferred_group_head == Some(group) {
            self.state.preferred_group_head = None;
        }
    }

    fn maybe_clear_idle_state(&mut self) {
        if self.state.has_retained_real_state()
            || !self.active_group_refs.is_empty()
            || !self.stream_group_buckets.is_empty()
        {
            return;
        }
        self.state.clear_idle_retained();
    }
}

#[derive(Debug, Default)]
struct BatchState {
    root_virtual_time: u64,
    group_virtual_time: HashMap<GroupKey, u64>,
    group_finish_tag: HashMap<GroupKey, u64>,
    group_last_service: HashMap<GroupKey, u64>,
    group_lag: HashMap<GroupKey, i64>,
    stream_finish_tag: HashMap<u64, u64>,
    stream_last_service: HashMap<u64, u64>,
    stream_lag: HashMap<u64, i64>,
    stream_class: HashMap<u64, TrafficClass>,
    stream_last_seen_batch: HashMap<u64, u64>,
    small_burst_disarmed: HashMap<u64, ()>,
    preferred_group_head: Option<GroupKey>,
    preferred_stream_head: HashMap<GroupKey, u64>,
    service_seq: u64,
    batch_seq: u64,
    interactive_streak: u32,
    class_selections_since_bulk: u32,
    scratch: BatchScratch,
}

impl BatchState {
    fn has_retained_real_state(&self) -> bool {
        !self.group_virtual_time.is_empty()
            || !self.group_finish_tag.is_empty()
            || !self.group_last_service.is_empty()
            || !self.stream_finish_tag.is_empty()
            || !self.stream_last_service.is_empty()
            || !self.stream_class.is_empty()
            || !self.stream_last_seen_batch.is_empty()
            || !self.small_burst_disarmed.is_empty()
            || !self.preferred_stream_head.is_empty()
            || self.preferred_group_head.is_some()
    }

    fn clear_idle_retained(&mut self) {
        *self = Self::default();
    }

    fn clear_idle_retained_preserving_heads(&mut self) {
        let preferred_group_head = self.preferred_group_head;
        let preferred_stream_head = mem::take(&mut self.preferred_stream_head);
        *self = Self::default();
        self.preferred_group_head = preferred_group_head;
        self.preferred_stream_head = preferred_stream_head;
    }
}

#[derive(Debug, Default)]
struct BatchScratch {
    groups: Vec<BatchBuiltGroup>,
    group_indices: HashMap<GroupKey, usize>,
    prepared_streams: Vec<PreparedStream>,
    prepared_stream_index: HashMap<u64, usize>,
    selected: Vec<bool>,
    recorded_group_head: Vec<bool>,
    bypass_selections: HashMap<u64, usize>,
    interactive_active: Vec<u64>,
    bulk_active: Vec<u64>,
    interactive_candidates: Vec<GroupCandidate>,
    bulk_candidates: Vec<GroupCandidate>,
    tie_pref_streams: HashMap<GroupKey, u64>,
}

#[derive(Debug)]
struct BatchBuildResult {
    groups: Vec<BatchBuiltGroup>,
    prepared_streams: Vec<PreparedStream>,
    prepared_stream_index: HashMap<u64, usize>,
    has_real_stream_scoped: bool,
    has_priority_update: bool,
}

impl BatchBuildResult {
    fn prepared_stream(&self, stream_id: u64) -> Option<&PreparedStream> {
        self.prepared_stream_index
            .get(&stream_id)
            .and_then(|index| self.prepared_streams.get(*index))
    }

    fn prepared_stream_mut(&mut self, stream_id: u64) -> Option<&mut PreparedStream> {
        let index = *self.prepared_stream_index.get(&stream_id)?;
        self.prepared_streams.get_mut(index)
    }
}

#[derive(Debug)]
struct BatchBuiltGroup {
    key: GroupKey,
    streams: Vec<BatchStreamQueue>,
    stream_index: Option<HashMap<u64, usize>>,
}

impl BatchBuiltGroup {
    fn queue_mut(&mut self, stream_id: u64) -> &mut BatchStreamQueue {
        if let Some(pos) = self
            .stream_index
            .as_ref()
            .and_then(|index| index.get(&stream_id).copied())
        {
            return &mut self.streams[pos];
        }
        if let Some(pos) = self
            .streams
            .iter()
            .position(|stream| stream.stream_id == stream_id)
        {
            if let Some(index) = self.stream_index.as_mut() {
                index.insert(stream_id, pos);
            }
            return &mut self.streams[pos];
        }
        let pos = self.streams.len();
        self.streams.push(BatchStreamQueue::new(stream_id));
        if let Some(index) = self.stream_index.as_mut() {
            index.insert(stream_id, pos);
        } else if self.streams.len() > GROUP_STREAM_INDEX_THRESHOLD {
            self.stream_index = Some(group_stream_index(&self.streams));
        }
        &mut self.streams[pos]
    }

    fn stream_mut(&mut self, stream_id: u64) -> Option<&mut BatchStreamQueue> {
        if let Some(pos) = self
            .stream_index
            .as_ref()
            .and_then(|index| index.get(&stream_id).copied())
        {
            return self.streams.get_mut(pos);
        }
        let pos = self
            .streams
            .iter()
            .position(|stream| stream.stream_id == stream_id)?;
        if let Some(index) = self.stream_index.as_mut() {
            index.insert(stream_id, pos);
        }
        self.streams.get_mut(pos)
    }
}

#[derive(Debug)]
struct BatchStreamQueue {
    stream_id: u64,
    queue: Vec<usize>,
    head: usize,
}

impl BatchStreamQueue {
    fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            queue: Vec::new(),
            head: 0,
        }
    }

    fn push(&mut self, req_idx: usize) {
        if self.head == self.queue.len() {
            self.queue.clear();
            self.head = 0;
        }
        self.queue.push(req_idx);
    }

    fn active(&self) -> &[usize] {
        self.queue.get(self.head..).unwrap_or(&[])
    }

    fn pop_front(&mut self) -> Option<usize> {
        let req_idx = *self.queue.get(self.head)?;
        self.head += 1;
        self.compact_consumed_head();
        Some(req_idx)
    }

    fn remove(&mut self, queue_pos: usize) -> Option<usize> {
        if queue_pos == self.head {
            return self.pop_front();
        }
        if queue_pos < self.head || queue_pos >= self.queue.len() {
            return None;
        }
        let req_idx = self.queue.remove(queue_pos);
        self.compact_consumed_head();
        Some(req_idx)
    }

    fn compact_consumed_head(&mut self) {
        if self.head == 0 {
            return;
        }
        if self.head >= self.queue.len() {
            self.queue.clear();
            self.head = 0;
            return;
        }
        if self.head >= STREAM_QUEUE_COMPACT_HEAD_MIN
            && self.head.saturating_mul(2) >= self.queue.len()
        {
            self.queue.drain(..self.head);
            self.head = 0;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PreparedStream {
    stream_id: u64,
    meta: StreamMeta,
    selection: Option<StreamSelection>,
    queued_bytes: u64,
    class: TrafficClass,
    small_burst_armed: bool,
}

#[derive(Debug, Clone, Copy)]
struct StreamSelection {
    req_idx: usize,
    queue_pos: usize,
    cost: i64,
    base_weight: u64,
    is_priority_update: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct StreamCandidate {
    stream_id: u64,
    req_idx: usize,
    queue_pos: usize,
    cost: i64,
    base_weight: u64,
    stream_start: u64,
    stream_finish: u64,
    stream_last_served: u64,
    eligible: bool,
    is_priority_update: bool,
    stream_order: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct GroupCandidate {
    group_key: GroupKey,
    group_start: u64,
    group_finish: u64,
    group_last_served: u64,
    eligible: bool,
    group_order: usize,
    class: Option<TrafficClass>,
    base_group_weight: u64,
    group_weight: u64,
    total_base_stream_weight: u64,
    total_stream_weight: u64,
    stream: StreamCandidate,
}

#[derive(Debug, Clone, Copy)]
struct CandidatePair {
    interactive: Option<GroupCandidate>,
    bulk: Option<GroupCandidate>,
}

#[derive(Debug, Clone, Copy)]
struct CandidateContext<'a> {
    cfg: BatchConfig,
    state: &'a BatchState,
    prepared: &'a BatchBuildResult,
    prefs: &'a TiePrefs,
    interactive_quantum: u64,
    feedback_window: i64,
    interactive_active: &'a [u64],
    bulk_active: &'a [u64],
    bypass_selections: &'a HashMap<u64, usize>,
}

#[derive(Debug, Clone, Copy)]
struct GroupCandidateState {
    group_key: GroupKey,
    group_order: usize,
    class: TrafficClass,
    total_base_stream_weight: u64,
    total_stream_weight: u64,
    feedback_window: i64,
    root_virtual: u64,
    group_finish_base: u64,
    group_last_served: u64,
    group_lag: i64,
    fresh_group: bool,
}

#[derive(Debug, Clone)]
struct TiePrefs {
    group: Option<GroupKey>,
    streams: HashMap<GroupKey, u64>,
}

#[derive(Debug)]
struct ActiveOrderScratch {
    tie_prefs: TiePrefs,
    selected: Vec<bool>,
    recorded_group_head: Vec<bool>,
    bypass_selections: HashMap<u64, usize>,
    interactive_active: Vec<u64>,
    bulk_active: Vec<u64>,
    interactive_candidates: Vec<GroupCandidate>,
    bulk_candidates: Vec<GroupCandidate>,
}

#[cfg(test)]
fn order_batch_indices(
    cfg: BatchConfig,
    state: &mut BatchState,
    items: &[BatchItem],
) -> Vec<usize> {
    let mut ordered = Vec::new();
    order_batch_indices_into(cfg, state, items, &mut ordered);
    ordered
}

fn order_batch_indices_into(
    cfg: BatchConfig,
    state: &mut BatchState,
    items: &[BatchItem],
    ordered: &mut Vec<usize>,
) {
    ordered.clear();
    if cfg.urgent {
        order_urgent_batch_into(items, ordered);
        return;
    }
    if items.len() < 2 {
        if !items.iter().any(|item| item.request.stream_scoped) && !state.has_retained_real_state()
        {
            state.clear_idle_retained_preserving_heads();
        }
        append_identity_order(ordered, items.len());
        return;
    }

    let retained_real_state = state.has_retained_real_state();
    if !retained_real_state {
        state.clear_idle_retained();
    }

    let mut prepared = build_batch_groups(state, items);
    if !prepared.has_real_stream_scoped {
        if !retained_real_state {
            drop(prepared);
            state.clear_idle_retained_preserving_heads();
        } else {
            recycle_build_scratch(state, prepared);
        }
        append_identity_order(ordered, items.len());
        return;
    }

    let tie_prefs = snapshot_tie_prefs(state);
    let interactive_quantum = scheduler_quantum(cfg.max_frame_payload);
    let feedback_window = feedback_window(cfg.scheduler_hint, cfg.max_frame_payload);
    let batch_seq = state.batch_seq.saturating_add(1);
    apply_batch_stream_classes(
        state,
        &mut prepared,
        cfg.scheduler_hint,
        interactive_quantum,
        batch_seq,
    );

    if ordered.capacity() < items.len() && ordered.try_reserve(items.len()).is_err() {
        recycle_build_scratch(state, prepared);
        return;
    }
    let mut selected = take_bool_scratch(&mut state.scratch.selected, items.len());
    let mut advisory_head_armed = true;
    let mut seen_real_opportunity = false;
    let mut transient_head_used = false;
    let mut recorded_batch_head = false;
    let mut recorded_group_head = take_bool_scratch(
        &mut state.scratch.recorded_group_head,
        prepared.groups.len(),
    );
    let mut interactive_streak = state.interactive_streak;
    let mut class_selections_since_bulk = state.class_selections_since_bulk;
    let mut bypass_selections = take_hashmap_scratch(
        &mut state.scratch.bypass_selections,
        prepared.prepared_streams.len(),
    );
    let mut interactive_active = take_vec_scratch(
        &mut state.scratch.interactive_active,
        prepared.prepared_streams.len(),
    );
    let mut bulk_active = take_vec_scratch(
        &mut state.scratch.bulk_active,
        prepared.prepared_streams.len(),
    );
    let mut interactive_candidates = take_vec_scratch(
        &mut state.scratch.interactive_candidates,
        prepared.groups.len(),
    );
    let mut bulk_candidates =
        take_vec_scratch(&mut state.scratch.bulk_candidates, prepared.groups.len());

    while ordered.len() < items.len() {
        if !seen_real_opportunity && !transient_head_used {
            if let Some(req_idx) = pop_next_transient_ordinary_head(&mut prepared.groups) {
                ordered.push(req_idx);
                selected[req_idx] = true;
                transient_head_used = true;
                continue;
            }
        }

        let advisory_only = advisory_head_armed && prepared.has_priority_update;
        refresh_active_stream_selections(
            &mut prepared,
            items,
            cfg,
            advisory_only,
            &mut interactive_active,
            &mut bulk_active,
        );

        interactive_candidates.clear();
        bulk_candidates.clear();
        let mut interactive_group_weight = 0u64;
        let mut bulk_group_weight = 0u64;
        let mut interactive_best = None;
        let mut bulk_best = None;

        for group_order in 0..prepared.groups.len() {
            let pair = top_candidates_for_group_classes(
                CandidateContext {
                    cfg,
                    state,
                    prepared: &prepared,
                    prefs: &tie_prefs,
                    interactive_quantum,
                    feedback_window,
                    interactive_active: &interactive_active,
                    bulk_active: &bulk_active,
                    bypass_selections: &bypass_selections,
                },
                group_order,
            );
            if let Some(candidate) = pair.interactive {
                interactive_group_weight =
                    interactive_group_weight.saturating_add(candidate.group_weight);
                if interactive_best
                    .is_none_or(|best| better_group_candidate(&tie_prefs, candidate, best))
                {
                    interactive_best = Some(candidate);
                }
                interactive_candidates.push(candidate);
            }
            if let Some(candidate) = pair.bulk {
                bulk_group_weight = bulk_group_weight.saturating_add(candidate.group_weight);
                if bulk_best.is_none_or(|best| better_group_candidate(&tie_prefs, candidate, best))
                {
                    bulk_best = Some(candidate);
                }
                bulk_candidates.push(candidate);
            }
        }

        if interactive_best.is_none() && bulk_best.is_none() {
            append_remaining_in_input_order(ordered, &mut selected, items.len());
            break;
        }

        let selected_class = choose_traffic_class(
            &tie_prefs,
            cfg.scheduler_hint,
            interactive_best,
            bulk_best,
            interactive_streak,
            class_selections_since_bulk,
        );
        let candidate_info = match selected_class {
            TrafficClass::Bulk => bulk_best
                .map(|candidate| {
                    (
                        candidate,
                        bulk_candidates.as_slice(),
                        bulk_group_weight,
                        bulk_active.as_slice(),
                    )
                })
                .or_else(|| {
                    interactive_best.map(|candidate| {
                        (
                            candidate,
                            interactive_candidates.as_slice(),
                            interactive_group_weight,
                            interactive_active.as_slice(),
                        )
                    })
                }),
            TrafficClass::Interactive => interactive_best
                .map(|candidate| {
                    (
                        candidate,
                        interactive_candidates.as_slice(),
                        interactive_group_weight,
                        interactive_active.as_slice(),
                    )
                })
                .or_else(|| {
                    bulk_best.map(|candidate| {
                        (
                            candidate,
                            bulk_candidates.as_slice(),
                            bulk_group_weight,
                            bulk_active.as_slice(),
                        )
                    })
                }),
        };
        let Some((candidate, candidates, total_group_weight, active_class_streams)) =
            candidate_info
        else {
            append_remaining_in_input_order(ordered, &mut selected, items.len());
            break;
        };

        ordered.push(candidate.stream.req_idx);
        selected[candidate.stream.req_idx] = true;
        record_preferred_heads(
            state,
            candidate,
            &prepared.groups,
            recorded_batch_head,
            &mut recorded_group_head,
        );
        recorded_batch_head = true;
        update_lag_feedback(
            state,
            &prepared,
            candidate,
            candidates,
            total_group_weight,
            feedback_window,
        );
        update_bypass_selections(
            active_class_streams,
            candidate.stream.stream_id,
            &mut bypass_selections,
        );
        if let Some(prepared_stream) = prepared.prepared_stream_mut(candidate.stream.stream_id) {
            if prepared_stream.small_burst_armed
                && prepared_stream.queued_bytes <= interactive_quantum
            {
                prepared_stream.small_burst_armed = false;
                state
                    .small_burst_disarmed
                    .insert(candidate.stream.stream_id, ());
            }
        }
        remove_group_queue_entry(
            &mut prepared.groups,
            candidate.group_order,
            candidate.stream.stream_id,
            candidate.stream.queue_pos,
        );
        consume_prepared_queued_bytes(
            &mut prepared,
            candidate.stream.stream_id,
            candidate.stream.cost,
        );
        commit_wfq_selection(
            state,
            candidate,
            total_group_weight.max(1),
            candidate.total_stream_weight.max(1),
        );
        if candidate.stream.is_priority_update {
            advisory_head_armed = false;
        }
        if !is_synthetic_stream_key(candidate.stream.stream_id) {
            seen_real_opportunity = true;
            match candidate.class {
                Some(TrafficClass::Bulk) => {
                    interactive_streak = 0;
                    class_selections_since_bulk = 0;
                }
                _ => {
                    interactive_streak = interactive_streak.saturating_add(1);
                    if interactive_best.is_some() && bulk_best.is_some() {
                        class_selections_since_bulk = class_selections_since_bulk.saturating_add(1);
                    } else {
                        class_selections_since_bulk = 0;
                    }
                }
            }
        }
    }

    retain_batch_stream_classes(
        state,
        &prepared.prepared_streams,
        batch_seq,
        interactive_streak,
        class_selections_since_bulk,
    );
    maybe_rebase_wfq_state(state);
    let order_scratch = ActiveOrderScratch {
        tie_prefs,
        selected,
        recorded_group_head,
        bypass_selections,
        interactive_active,
        bulk_active,
        interactive_candidates,
        bulk_candidates,
    };
    recycle_order_scratch(state, prepared, order_scratch);
}

fn build_batch_groups(state: &mut BatchState, items: &[BatchItem]) -> BatchBuildResult {
    let mut groups = take_vec_scratch(&mut state.scratch.groups, items.len());
    let mut group_indices = take_hashmap_scratch(&mut state.scratch.group_indices, items.len());
    let mut prepared_streams = take_vec_scratch(&mut state.scratch.prepared_streams, items.len());
    let mut prepared_stream_index =
        take_hashmap_scratch(&mut state.scratch.prepared_stream_index, items.len());
    let mut has_real_stream_scoped = false;
    let mut has_priority_update = false;

    for (idx, item) in items.iter().enumerate() {
        let req = item.request;
        let group_idx = group_index(&mut groups, &mut group_indices, req.group_key);
        let stream_key = synthetic_stream_key(req, idx);
        groups[group_idx].queue_mut(stream_key).push(idx);
        let cost = normalize_cost_u64(req.cost);
        if req.stream_scoped {
            has_real_stream_scoped = true;
            if let Some(prepared_idx) = prepared_stream_index.get(&req.stream_id).copied() {
                let prepared = &mut prepared_streams[prepared_idx];
                prepared.meta = item.stream;
                prepared.queued_bytes = prepared.queued_bytes.saturating_add(cost);
            } else {
                let prepared_idx = prepared_streams.len();
                prepared_streams.push(PreparedStream {
                    stream_id: req.stream_id,
                    meta: item.stream,
                    selection: None,
                    queued_bytes: cost,
                    class: TrafficClass::Interactive,
                    small_burst_armed: false,
                });
                prepared_stream_index.insert(req.stream_id, prepared_idx);
            }
        }
        if req.is_priority_update {
            has_priority_update = true;
        }
    }

    group_indices.clear();
    state.scratch.group_indices = group_indices;
    BatchBuildResult {
        groups,
        prepared_streams,
        prepared_stream_index,
        has_real_stream_scoped,
        has_priority_update,
    }
}

fn recycle_build_scratch(state: &mut BatchState, mut prepared: BatchBuildResult) {
    prepared.groups.clear();
    prepared.prepared_streams.clear();
    prepared.prepared_stream_index.clear();
    state.scratch.groups = prepared.groups;
    state.scratch.prepared_streams = prepared.prepared_streams;
    state.scratch.prepared_stream_index = prepared.prepared_stream_index;
}

fn recycle_order_scratch(
    state: &mut BatchState,
    prepared: BatchBuildResult,
    mut scratch: ActiveOrderScratch,
) {
    recycle_build_scratch(state, prepared);
    scratch.tie_prefs.streams.clear();
    scratch.selected.clear();
    scratch.recorded_group_head.clear();
    scratch.bypass_selections.clear();
    scratch.interactive_active.clear();
    scratch.bulk_active.clear();
    scratch.interactive_candidates.clear();
    scratch.bulk_candidates.clear();
    state.scratch.tie_pref_streams = scratch.tie_prefs.streams;
    state.scratch.selected = scratch.selected;
    state.scratch.recorded_group_head = scratch.recorded_group_head;
    state.scratch.bypass_selections = scratch.bypass_selections;
    state.scratch.interactive_active = scratch.interactive_active;
    state.scratch.bulk_active = scratch.bulk_active;
    state.scratch.interactive_candidates = scratch.interactive_candidates;
    state.scratch.bulk_candidates = scratch.bulk_candidates;
}

fn take_vec_scratch<T>(slot: &mut Vec<T>, capacity: usize) -> Vec<T> {
    let mut out = if batch_scratch_oversized(slot.capacity(), capacity) {
        Vec::new()
    } else {
        mem::take(slot)
    };
    out.clear();
    reserve_vec_capacity(&mut out, capacity);
    out
}

fn take_bool_scratch(slot: &mut Vec<bool>, len: usize) -> Vec<bool> {
    let mut out = take_vec_scratch(slot, len);
    out.resize(len, false);
    out
}

fn take_hashmap_scratch<K, V>(slot: &mut HashMap<K, V>, capacity: usize) -> HashMap<K, V>
where
    K: Eq + Hash,
{
    let mut out = if batch_scratch_oversized(slot.capacity(), capacity) {
        HashMap::new()
    } else {
        mem::take(slot)
    };
    out.clear();
    reserve_hashmap_capacity(&mut out, capacity);
    out
}

fn reserve_vec_capacity<T>(values: &mut Vec<T>, capacity: usize) {
    if values.capacity() < capacity {
        values.reserve(capacity.saturating_sub(values.len()));
    }
}

fn batch_scratch_oversized(retained_capacity: usize, capacity_hint: usize) -> bool {
    retained_capacity > batch_scratch_retain_limit(capacity_hint)
}

fn batch_scratch_retain_limit(capacity_hint: usize) -> usize {
    capacity_hint
        .max(MIN_BATCH_SCRATCH_RETAIN_HINT)
        .saturating_mul(BATCH_SCRATCH_RETAIN_FACTOR)
}

fn reserve_hashmap_capacity<K, V>(values: &mut HashMap<K, V>, capacity: usize)
where
    K: Eq + Hash,
{
    if values.capacity() < capacity {
        values.reserve(capacity.saturating_sub(values.len()));
    }
}

fn group_index(
    groups: &mut Vec<BatchBuiltGroup>,
    group_indices: &mut HashMap<GroupKey, usize>,
    group_key: GroupKey,
) -> usize {
    if let Some(index) = group_indices.get(&group_key).copied() {
        return index;
    }
    let index = groups.len();
    groups.push(BatchBuiltGroup {
        key: group_key,
        streams: Vec::new(),
        stream_index: None,
    });
    group_indices.insert(group_key, index);
    index
}

fn group_stream_index(streams: &[BatchStreamQueue]) -> HashMap<u64, usize> {
    let mut index = HashMap::with_capacity(streams.len());
    for (pos, stream) in streams.iter().enumerate() {
        index.insert(stream.stream_id, pos);
    }
    index
}

fn synthetic_stream_key(req: RequestMeta, idx: usize) -> u64 {
    if req.stream_scoped {
        req.stream_id
    } else {
        SYNTHETIC_STREAM_KEY_BIT | usize_to_u64_saturating(idx)
    }
}

fn is_synthetic_stream_key(stream_id: u64) -> bool {
    stream_id & SYNTHETIC_STREAM_KEY_BIT != 0
}

fn pop_next_transient_ordinary_head(groups: &mut [BatchBuiltGroup]) -> Option<usize> {
    for group in groups.iter_mut() {
        if !group.key.is_transient() {
            continue;
        }
        for stream in &mut group.streams {
            if let Some(req_idx) = stream.pop_front() {
                return Some(req_idx);
            }
        }
    }
    None
}

fn apply_batch_stream_classes(
    state: &mut BatchState,
    prepared: &mut BatchBuildResult,
    hint: SchedulerHint,
    interactive_quantum: u64,
    batch_seq: u64,
) {
    for prepared_stream in &mut prepared.prepared_streams {
        let stream_id = prepared_stream.stream_id;
        let previous = state.stream_class.get(&stream_id).copied();
        let class = classify_stream_class(
            prepared_stream.queued_bytes,
            prepared_stream.meta.priority,
            hint,
            previous,
            interactive_quantum,
        );
        if state
            .stream_last_seen_batch
            .get(&stream_id)
            .is_none_or(|last| batch_seq.saturating_sub(*last) >= 2)
        {
            state.small_burst_disarmed.remove(&stream_id);
        }
        prepared_stream.selection = None;
        prepared_stream.class = class;
        prepared_stream.small_burst_armed = !state.small_burst_disarmed.contains_key(&stream_id);
    }
}

fn refresh_active_stream_selections(
    prepared: &mut BatchBuildResult,
    items: &[BatchItem],
    cfg: BatchConfig,
    advisory_only: bool,
    interactive_active: &mut Vec<u64>,
    bulk_active: &mut Vec<u64>,
) {
    for prepared_stream in &mut prepared.prepared_streams {
        prepared_stream.selection = None;
    }
    interactive_active.clear();
    bulk_active.clear();
    for group_idx in 0..prepared.groups.len() {
        for stream_idx in 0..prepared.groups[group_idx].streams.len() {
            let stream_queue = &prepared.groups[group_idx].streams[stream_idx];
            let stream_id = stream_queue.stream_id;
            let Some((req_idx, queue_pos, cost, is_priority_update)) =
                select_stream_candidate(stream_queue, items, advisory_only)
            else {
                continue;
            };
            let Some(prepared_stream) = prepared.prepared_stream_mut(stream_id) else {
                continue;
            };
            prepared_stream.selection = Some(StreamSelection {
                req_idx,
                queue_pos,
                cost,
                base_weight: stream_weight(
                    prepared_stream.meta.priority,
                    prepared_stream.queued_bytes,
                    cfg.scheduler_hint,
                    cfg.max_frame_payload,
                ),
                is_priority_update,
            });
            match prepared_stream.class {
                TrafficClass::Bulk => bulk_active.push(stream_id),
                TrafficClass::Interactive => interactive_active.push(stream_id),
            }
        }
    }
}

fn select_stream_candidate(
    stream: &BatchStreamQueue,
    items: &[BatchItem],
    advisory_only: bool,
) -> Option<(usize, usize, i64, bool)> {
    for (offset, &idx) in stream.active().iter().enumerate() {
        if items[idx].request.is_priority_update {
            let pos = stream.head + offset;
            return Some((idx, pos, normalize_cost(items[idx].request.cost), true));
        }
    }
    if advisory_only {
        return None;
    }
    let idx = *stream.active().first()?;
    Some((
        idx,
        stream.head,
        normalize_cost(items[idx].request.cost),
        false,
    ))
}

fn top_candidates_for_group_classes(
    ctx: CandidateContext<'_>,
    group_order: usize,
) -> CandidatePair {
    let group = &ctx.prepared.groups[group_order];
    let group_virtual = group_virtual_time(ctx.state, group.key);
    let group_finish_base = group_finish_tag(ctx.state, group.key);
    let group_lag_value = group_lag(ctx.state, group.key);
    let group_last_served_value = group_last_served(ctx.state, group.key);
    let fresh_group = is_fresh_group(ctx.state, group.key);
    let root_virtual = ctx.state.root_virtual_time;
    let preferred_stream = tie_pref_stream(ctx.prefs, group.key);
    let mut interactive_top = None;
    let mut bulk_top = None;
    let mut total_interactive_base = 0u64;
    let mut total_interactive_weight = 0u64;
    let mut total_bulk_base = 0u64;
    let mut total_bulk_weight = 0u64;

    for (stream_order, stream_queue) in group.streams.iter().enumerate() {
        let stream_id = stream_queue.stream_id;
        let Some(prepared_stream) = ctx.prepared.prepared_stream(stream_id) else {
            continue;
        };
        let Some(selection) = prepared_stream.selection else {
            continue;
        };
        let base_weight = selection.base_weight;
        let lag_adjusted_weight = adjust_weight_for_lag(
            base_weight,
            stream_lag(ctx.state, stream_id),
            ctx.feedback_window,
            is_fresh_stream(ctx.state, stream_id),
        );
        let active_class_streams = match prepared_stream.class {
            TrafficClass::Bulk => ctx.bulk_active.len(),
            TrafficClass::Interactive => ctx.interactive_active.len(),
        };
        let effective_weight = class_adjusted_weight(
            base_weight,
            lag_adjusted_weight,
            prepared_stream.queued_bytes,
            prepared_stream.small_burst_armed,
            ctx.interactive_quantum,
            should_apply_aging(stream_id, active_class_streams, ctx.bypass_selections),
        );
        let stream_start = stream_finish_tag(ctx.state, stream_id).max(group_virtual);
        let stream_finish =
            stream_start.saturating_add(service_tag(selection.cost, effective_weight.max(1)));
        let candidate = StreamCandidate {
            stream_id,
            req_idx: selection.req_idx,
            queue_pos: selection.queue_pos,
            cost: selection.cost,
            base_weight,
            stream_start,
            stream_finish,
            stream_last_served: stream_last_served(ctx.state, stream_id),
            eligible: stream_start <= group_virtual,
            is_priority_update: selection.is_priority_update,
            stream_order,
        };
        match prepared_stream.class {
            TrafficClass::Bulk => {
                total_bulk_base = total_bulk_base.saturating_add(base_weight);
                total_bulk_weight = total_bulk_weight.saturating_add(effective_weight);
                if bulk_top
                    .is_none_or(|top| better_stream_candidate(preferred_stream, candidate, top))
                {
                    bulk_top = Some(candidate);
                }
            }
            TrafficClass::Interactive => {
                total_interactive_base = total_interactive_base.saturating_add(base_weight);
                total_interactive_weight =
                    total_interactive_weight.saturating_add(effective_weight);
                if interactive_top
                    .is_none_or(|top| better_stream_candidate(preferred_stream, candidate, top))
                {
                    interactive_top = Some(candidate);
                }
            }
        }
    }

    CandidatePair {
        interactive: interactive_top.map(|top| {
            build_group_class_candidate(
                ctx.cfg,
                GroupCandidateState {
                    group_key: group.key,
                    group_order,
                    class: TrafficClass::Interactive,
                    total_base_stream_weight: total_interactive_base,
                    total_stream_weight: total_interactive_weight,
                    feedback_window: ctx.feedback_window,
                    root_virtual,
                    group_finish_base,
                    group_last_served: group_last_served_value,
                    group_lag: group_lag_value,
                    fresh_group,
                },
                top,
            )
        }),
        bulk: bulk_top.map(|top| {
            build_group_class_candidate(
                ctx.cfg,
                GroupCandidateState {
                    group_key: group.key,
                    group_order,
                    class: TrafficClass::Bulk,
                    total_base_stream_weight: total_bulk_base,
                    total_stream_weight: total_bulk_weight,
                    feedback_window: ctx.feedback_window,
                    root_virtual,
                    group_finish_base,
                    group_last_served: group_last_served_value,
                    group_lag: group_lag_value,
                    fresh_group,
                },
                top,
            )
        }),
    }
}

fn build_group_class_candidate(
    cfg: BatchConfig,
    group_state: GroupCandidateState,
    top: StreamCandidate,
) -> GroupCandidate {
    let base_group_weight =
        group_weight(group_state.group_key, top.base_weight, cfg.scheduler_hint);
    let adjusted_group_weight = adjust_weight_for_lag(
        base_group_weight,
        group_state.group_lag,
        group_state.feedback_window,
        group_state.fresh_group,
    );
    let group_start = group_state.group_finish_base.max(group_state.root_virtual);
    let group_finish =
        group_start.saturating_add(service_tag(top.cost, adjusted_group_weight.max(1)));
    GroupCandidate {
        group_key: group_state.group_key,
        group_start,
        group_finish,
        group_last_served: group_state.group_last_served,
        eligible: group_start <= group_state.root_virtual && top.eligible,
        group_order: group_state.group_order,
        class: Some(group_state.class),
        base_group_weight: base_group_weight.max(1),
        group_weight: adjusted_group_weight.max(1),
        total_base_stream_weight: group_state.total_base_stream_weight.max(1),
        total_stream_weight: group_state.total_stream_weight.max(1),
        stream: top,
    }
}

fn choose_traffic_class(
    prefs: &TiePrefs,
    hint: SchedulerHint,
    interactive: Option<GroupCandidate>,
    bulk: Option<GroupCandidate>,
    interactive_streak: u32,
    class_selections_since_bulk: u32,
) -> TrafficClass {
    let Some(interactive) = interactive else {
        return TrafficClass::Bulk;
    };
    let Some(bulk) = bulk else {
        return TrafficClass::Interactive;
    };
    if interactive_streak >= INTERACTIVE_BURST_LIMIT
        || class_selections_since_bulk >= BULK_RESERVE_WINDOW.saturating_sub(1)
    {
        return TrafficClass::Bulk;
    }
    if better_class_candidate(prefs, interactive, bulk, hint) {
        TrafficClass::Interactive
    } else {
        TrafficClass::Bulk
    }
}

fn better_class_candidate(
    prefs: &TiePrefs,
    left: GroupCandidate,
    right: GroupCandidate,
    hint: SchedulerHint,
) -> bool {
    if left.eligible != right.eligible {
        return left.eligible;
    }
    let mut left_primary = scaled_class_tag(left, hint, left.group_start);
    let mut right_primary = scaled_class_tag(right, hint, right.group_start);
    if left.eligible {
        left_primary = scaled_class_tag(left, hint, left.group_finish);
        right_primary = scaled_class_tag(right, hint, right.group_finish);
    }
    if left_primary != right_primary {
        return left_primary < right_primary;
    }
    let mut left_secondary = scaled_class_tag(left, hint, left.group_finish);
    let mut right_secondary = scaled_class_tag(right, hint, right.group_finish);
    if left.eligible {
        left_secondary = scaled_class_tag(left, hint, left.group_start);
        right_secondary = scaled_class_tag(right, hint, right.group_start);
    }
    if left_secondary != right_secondary {
        return left_secondary < right_secondary;
    }
    better_group_candidate(prefs, left, right)
}

fn scaled_class_tag(candidate: GroupCandidate, hint: SchedulerHint, tag: u64) -> u64 {
    let weight = class_bias_weight(candidate.class.unwrap_or(TrafficClass::Interactive), hint);
    if weight == 0 {
        tag
    } else {
        saturating_mul_div_floor(tag, CLASS_SCORE_SCALE, weight)
    }
}

fn class_bias_weight(class: TrafficClass, hint: SchedulerHint) -> u64 {
    match hint {
        SchedulerHint::Latency => match class {
            TrafficClass::Interactive => 8,
            TrafficClass::Bulk => 2,
        },
        SchedulerHint::BulkThroughput => match class {
            TrafficClass::Interactive => 2,
            TrafficClass::Bulk => 8,
        },
        _ => match class {
            TrafficClass::Interactive => 6,
            TrafficClass::Bulk => 4,
        },
    }
}

fn update_lag_feedback(
    state: &mut BatchState,
    prepared: &BatchBuildResult,
    chosen: GroupCandidate,
    candidates: &[GroupCandidate],
    total_group_weight: u64,
    feedback_window: i64,
) {
    if feedback_window <= 0 || chosen.stream.stream_id == 0 {
        return;
    }
    let cost = normalize_cost(chosen.stream.cost);
    for &candidate in candidates {
        let expected = fair_share(cost, candidate.base_group_weight, total_group_weight.max(1));
        let actual = if candidate.group_key == chosen.group_key {
            cost
        } else {
            0
        };
        let next = apply_lag_feedback(
            group_lag(state, candidate.group_key),
            expected,
            actual,
            feedback_window,
        );
        if !candidate.group_key.is_transient() {
            state.group_lag.insert(candidate.group_key, next);
        }
    }

    let chosen_class = chosen.class.unwrap_or(TrafficClass::Interactive);
    for stream_queue in &prepared.groups[chosen.group_order].streams {
        let stream_id = stream_queue.stream_id;
        let Some(prepared_stream) = prepared.prepared_stream(stream_id) else {
            continue;
        };
        let Some(selection) = prepared_stream.selection else {
            continue;
        };
        if prepared_stream.class != chosen_class {
            continue;
        }
        let expected = fair_share(
            cost,
            selection.base_weight,
            chosen.total_base_stream_weight.max(1),
        );
        let actual = if stream_id == chosen.stream.stream_id {
            cost
        } else {
            0
        };
        let next = apply_lag_feedback(
            stream_lag(state, stream_id),
            expected,
            actual,
            feedback_window,
        );
        if !is_synthetic_stream_key(stream_id) {
            state.stream_lag.insert(stream_id, next);
        }
    }
}

fn update_bypass_selections(
    active_streams: &[u64],
    selected_stream_id: u64,
    bypass_selections: &mut HashMap<u64, usize>,
) {
    for &stream_id in active_streams {
        if is_synthetic_stream_key(stream_id) {
            continue;
        }
        if stream_id == selected_stream_id {
            bypass_selections.insert(stream_id, 0);
        } else {
            let count = bypass_selections.entry(stream_id).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
}

fn bypass_count(bypass_selections: &HashMap<u64, usize>, stream_id: u64) -> usize {
    bypass_selections.get(&stream_id).copied().unwrap_or(0)
}

fn should_apply_aging(
    stream_id: u64,
    active_class_streams: usize,
    bypass_selections: &HashMap<u64, usize>,
) -> bool {
    active_class_streams > 1
        && bypass_count(bypass_selections, stream_id)
        >= active_class_streams.saturating_mul(AGING_ROUND_THRESHOLD)
}

fn class_adjusted_weight(
    base_weight: u64,
    effective_weight: u64,
    queued_bytes: u64,
    small_burst_armed: bool,
    interactive_quantum: u64,
    age_boost: bool,
) -> u64 {
    let mut adjusted = effective_weight.max(1);
    if small_burst_armed && queued_bytes <= interactive_quantum {
        adjusted = adjusted.saturating_add(base_weight.max(1));
    }
    if age_boost {
        adjusted = adjusted.saturating_add(base_weight.max(adjusted / 2).max(1));
    }
    adjusted.max(1)
}

fn consume_prepared_queued_bytes(prepared: &mut BatchBuildResult, stream_id: u64, cost: i64) {
    let delta = normalize_cost_u64(cost);
    if let Some(prepared_stream) = prepared.prepared_stream_mut(stream_id) {
        prepared_stream.queued_bytes = prepared_stream.queued_bytes.saturating_sub(delta);
    }
}

fn remove_group_queue_entry(
    groups: &mut [BatchBuiltGroup],
    group_order: usize,
    stream_id: u64,
    queue_pos: usize,
) {
    let Some(group) = groups.get_mut(group_order) else {
        return;
    };
    let Some(stream) = group.stream_mut(stream_id) else {
        return;
    };
    stream.remove(queue_pos);
}

fn commit_wfq_selection(
    state: &mut BatchState,
    candidate: GroupCandidate,
    active_group_weight: u64,
    active_stream_weight: u64,
) {
    state.service_seq = state.service_seq.saturating_add(1);
    let seq = state.service_seq;

    let root_virtual = state.root_virtual_time.max(candidate.group_start);
    state.root_virtual_time = root_virtual.saturating_add(service_tag(
        candidate.stream.cost,
        active_group_weight.max(1),
    ));

    let group_virtual =
        group_virtual_time(state, candidate.group_key).max(candidate.stream.stream_start);
    if !candidate.group_key.is_transient() {
        state.group_virtual_time.insert(
            candidate.group_key,
            group_virtual.saturating_add(service_tag(
                candidate.stream.cost,
                active_stream_weight.max(1),
            )),
        );
        state
            .group_finish_tag
            .insert(candidate.group_key, candidate.group_finish);
        state.group_last_service.insert(candidate.group_key, seq);
    }
    if !is_synthetic_stream_key(candidate.stream.stream_id) {
        state
            .stream_finish_tag
            .insert(candidate.stream.stream_id, candidate.stream.stream_finish);
        state
            .stream_last_service
            .insert(candidate.stream.stream_id, seq);
    }
}

fn retain_batch_stream_classes(
    state: &mut BatchState,
    prepared_streams: &[PreparedStream],
    batch_seq: u64,
    interactive_streak: u32,
    class_selections_since_bulk: u32,
) {
    for prepared_stream in prepared_streams {
        state
            .stream_class
            .insert(prepared_stream.stream_id, prepared_stream.class);
        state
            .stream_last_seen_batch
            .insert(prepared_stream.stream_id, batch_seq);
    }
    state.batch_seq = batch_seq;
    state.interactive_streak = interactive_streak;
    state.class_selections_since_bulk = class_selections_since_bulk;
}

fn record_preferred_heads(
    state: &mut BatchState,
    candidate: GroupCandidate,
    groups: &[BatchBuiltGroup],
    recorded_batch_head: bool,
    recorded_group_head: &mut [bool],
) {
    if is_synthetic_stream_key(candidate.stream.stream_id) {
        return;
    }
    if !recorded_batch_head {
        state.preferred_group_head = next_real_group_head(groups, candidate.group_order);
    }
    if recorded_group_head
        .get(candidate.group_order)
        .copied()
        .unwrap_or(true)
    {
        return;
    }
    recorded_group_head[candidate.group_order] = true;
    if let Some(next_stream) = next_real_stream_head(
        &groups[candidate.group_order].streams,
        candidate.stream.stream_order,
    ) {
        state
            .preferred_stream_head
            .insert(candidate.group_key, next_stream);
    } else {
        state.preferred_stream_head.remove(&candidate.group_key);
    }
}

fn next_real_group_head(groups: &[BatchBuiltGroup], selected: usize) -> Option<GroupKey> {
    if groups.len() < 2 {
        return None;
    }
    for offset in 1..groups.len() {
        let next = groups[(selected + offset) % groups.len()].key;
        if !next.is_transient() {
            return Some(next);
        }
    }
    None
}

fn next_real_stream_head(streams: &[BatchStreamQueue], selected: usize) -> Option<u64> {
    if streams.len() < 2 {
        return None;
    }
    for offset in 1..streams.len() {
        let next = streams[(selected + offset) % streams.len()].stream_id;
        if !is_synthetic_stream_key(next) {
            return Some(next);
        }
    }
    None
}

fn append_remaining_in_input_order(ordered: &mut Vec<usize>, selected: &mut [bool], size: usize) {
    for (idx, selected) in selected.iter_mut().enumerate().take(size) {
        if !*selected {
            ordered.push(idx);
            *selected = true;
        }
    }
}

fn append_identity_order(order: &mut Vec<usize>, n: usize) {
    order.clear();
    if order.capacity() < n && order.try_reserve(n).is_err() {
        return;
    }
    order.extend(0..n);
}

fn order_urgent_batch_into(items: &[BatchItem], order: &mut Vec<usize>) {
    append_identity_order(order, items.len());
    order.sort_by(|&left, &right| {
        let left_req = items[left].request;
        let right_req = items[right].request;
        left_req
            .urgency_rank
            .cmp(&right_req.urgency_rank)
            .then_with(|| right_req.stream_scoped.cmp(&left_req.stream_scoped))
            .then_with(|| {
                if left_req.stream_scoped && right_req.stream_scoped {
                    left_req.stream_id.cmp(&right_req.stream_id)
                } else {
                    std::cmp::Ordering::Equal
                }
            })
    });
}

#[cfg(test)]
fn order_urgent_batch(items: &[BatchItem]) -> Vec<usize> {
    let mut order = Vec::new();
    order_urgent_batch_into(items, &mut order);
    order
}

fn better_group_candidate(prefs: &TiePrefs, left: GroupCandidate, right: GroupCandidate) -> bool {
    if left.eligible != right.eligible {
        return left.eligible;
    }
    if let Some(result) = better_eligible_window(
        left.eligible,
        left.group_start,
        left.group_finish,
        right.group_start,
        right.group_finish,
    ) {
        return result;
    }
    if let Some(preferred) = prefs.group {
        let left_preferred = left.group_key == preferred;
        let right_preferred = right.group_key == preferred;
        if left_preferred != right_preferred {
            return left_preferred;
        }
    }
    if left.stream.stream_finish != right.stream.stream_finish {
        return left.stream.stream_finish < right.stream.stream_finish;
    }
    if left.stream.stream_start != right.stream.stream_start {
        return left.stream.stream_start < right.stream.stream_start;
    }
    if left.group_last_served != right.group_last_served {
        return left.group_last_served < right.group_last_served;
    }
    if left.stream.stream_last_served != right.stream.stream_last_served {
        return left.stream.stream_last_served < right.stream.stream_last_served;
    }
    if left.group_order != right.group_order {
        return left.group_order < right.group_order;
    }
    left.stream.stream_order < right.stream.stream_order
}

fn better_stream_candidate(
    preferred: Option<u64>,
    left: StreamCandidate,
    right: StreamCandidate,
) -> bool {
    if left.eligible != right.eligible {
        return left.eligible;
    }
    if let Some(result) = better_eligible_window(
        left.eligible,
        left.stream_start,
        left.stream_finish,
        right.stream_start,
        right.stream_finish,
    ) {
        return result;
    }
    if let Some(preferred) = preferred {
        let left_preferred = left.stream_id == preferred;
        let right_preferred = right.stream_id == preferred;
        if left_preferred != right_preferred {
            return left_preferred;
        }
    }
    if left.stream_last_served != right.stream_last_served {
        return left.stream_last_served < right.stream_last_served;
    }
    left.stream_order < right.stream_order
}

fn better_eligible_window(
    left_eligible: bool,
    left_start: u64,
    left_finish: u64,
    right_start: u64,
    right_finish: u64,
) -> Option<bool> {
    if !left_eligible {
        if left_start != right_start {
            return Some(left_start < right_start);
        }
        if left_finish != right_finish {
            return Some(left_finish < right_finish);
        }
        return None;
    }
    if left_finish != right_finish {
        return Some(left_finish < right_finish);
    }
    if left_start != right_start {
        return Some(left_start < right_start);
    }
    None
}

fn snapshot_tie_prefs(state: &mut BatchState) -> TiePrefs {
    let mut streams = take_hashmap_scratch(
        &mut state.scratch.tie_pref_streams,
        state.preferred_stream_head.len(),
    );
    streams.extend(
        state
            .preferred_stream_head
            .iter()
            .map(|(group, stream)| (*group, *stream)),
    );
    TiePrefs {
        group: state.preferred_group_head,
        streams,
    }
}

fn tie_pref_stream(prefs: &TiePrefs, group_key: GroupKey) -> Option<u64> {
    prefs.streams.get(&group_key).copied()
}

fn classify_stream_class(
    queued_bytes: u64,
    priority: u64,
    hint: SchedulerHint,
    previous: Option<TrafficClass>,
    mut interactive_quantum: u64,
) -> TrafficClass {
    if interactive_quantum == 0 {
        interactive_quantum = scheduler_quantum(0);
    }
    let bulk_threshold = interactive_quantum.saturating_mul(BULK_ENTRY_MULTIPLIER);
    if queued_bytes <= interactive_quantum {
        return TrafficClass::Interactive;
    }
    if queued_bytes > bulk_threshold {
        return TrafficClass::Bulk;
    }
    if let Some(previous) = previous {
        return previous;
    }
    if hint == SchedulerHint::BulkThroughput {
        TrafficClass::Bulk
    } else if hint == SchedulerHint::Latency || priority >= 4 {
        TrafficClass::Interactive
    } else if write_burst_limit(priority, hint) >= DEFAULT_WRITE_BURST_FRAMES {
        TrafficClass::Bulk
    } else {
        TrafficClass::Interactive
    }
}

pub(super) fn write_burst_limit(priority: u64, hint: SchedulerHint) -> u32 {
    match priority {
        16..=u64::MAX => SATURATED_WRITE_BURST_FRAMES,
        4..=15 => STRONG_WRITE_BURST_FRAMES,
        1..=3 => MILD_WRITE_BURST_FRAMES,
        0 if hint == SchedulerHint::Latency => MILD_WRITE_BURST_FRAMES,
        0 => DEFAULT_WRITE_BURST_FRAMES,
    }
}

fn scheduler_quantum(max_payload: u64) -> u64 {
    if max_payload == 0 {
        Settings::default().max_frame_payload
    } else {
        max_payload
    }
}

fn stream_weight(priority: u64, queued_bytes: u64, hint: SchedulerHint, max_payload: u64) -> u64 {
    let mut base = priority_weight(priority, hint);
    let short_window = scheduler_quantum(max_payload);
    if short_window == 0 {
        return base.max(1);
    }
    match hint {
        SchedulerHint::Latency => {
            if queued_bytes <= short_window {
                base = base.saturating_mul(4);
            } else if queued_bytes <= short_window.saturating_mul(2) {
                base = base.saturating_mul(2);
            }
        }
        SchedulerHint::BalancedFair
        | SchedulerHint::UnspecifiedOrBalanced
        | SchedulerHint::GroupFair => {
            if queued_bytes <= short_window {
                base = base.saturating_mul(2);
            }
        }
        SchedulerHint::BulkThroughput => {
            if short_window > 1 && queued_bytes <= short_window / 2 {
                base = base.saturating_add(base / 2);
            }
        }
    }
    base.max(1)
}

fn feedback_window(hint: SchedulerHint, max_payload: u64) -> i64 {
    let window = match hint {
        SchedulerHint::Latency => scheduler_quantum(max_payload).saturating_mul(6),
        SchedulerHint::BulkThroughput => scheduler_quantum(max_payload).saturating_mul(2),
        _ => scheduler_quantum(max_payload).saturating_mul(4),
    };
    if window == 0 {
        1
    } else {
        u64_to_i64_saturating(window)
    }
}

fn adjust_weight_for_lag(base: u64, lag: i64, window: i64, fresh: bool) -> u64 {
    let mut base = base.max(1);
    if fresh {
        base = base.saturating_add((base / 2).max(1));
    }
    if window <= 0 || lag == 0 {
        return base.max(1);
    }
    let window_u64 = i64_to_u64_saturating(window);
    if lag > 0 {
        let boost = lag_scaled_weight(base, lag.min(window), window_u64);
        return base.saturating_add(boost.max(1)).max(1);
    }
    let penalty = lag_scaled_weight(
        base,
        lag.saturating_abs().min(window),
        window_u64.saturating_mul(2),
    );
    base.saturating_sub(penalty).max(1)
}

fn lag_scaled_weight(base: u64, magnitude: i64, divisor: u64) -> u64 {
    if base == 0 || magnitude <= 0 || divisor == 0 {
        0
    } else {
        saturating_mul_div_floor(base, i64_to_u64_saturating(magnitude), divisor)
    }
}

fn group_weight(group_key: GroupKey, stream_weight: u64, hint: SchedulerHint) -> u64 {
    if group_key.kind != 1 {
        return stream_weight.max(1);
    }
    match hint {
        SchedulerHint::Latency => 32,
        SchedulerHint::BulkThroughput => 16,
        _ => 24,
    }
}

fn priority_weight(priority: u64, hint: SchedulerHint) -> u64 {
    match hint {
        SchedulerHint::Latency => banded_weight(priority, 16, 24, 32, 48, 64, 96),
        SchedulerHint::BulkThroughput => banded_weight(priority, 16, 18, 20, 24, 28, 32),
        _ => banded_weight(priority, 16, 20, 24, 32, 48, 72),
    }
}

fn banded_weight(
    priority: u64,
    base: u64,
    mild: u64,
    medium: u64,
    strong: u64,
    xstrong: u64,
    saturated: u64,
) -> u64 {
    match priority {
        32..=u64::MAX => saturated,
        16..=31 => xstrong,
        8..=15 => strong,
        4..=7 => medium,
        1..=3 => mild,
        0 => base,
    }
}

fn service_tag(cost: i64, weight: u64) -> u64 {
    let total = saturating_mul_div_ceil(normalize_cost_u64(cost), WFQ_TAG_SCALE, weight.max(1));
    total.max(1)
}

fn normalize_cost(cost: i64) -> i64 {
    cost.max(1)
}

fn normalize_cost_u64(cost: i64) -> u64 {
    i64_to_u64_saturating(normalize_cost(cost))
}

fn fair_share(cost: i64, weight: u64, total_weight: u64) -> i64 {
    if cost <= 0 || weight == 0 || total_weight == 0 {
        return 0;
    }
    u64_to_i64_saturating(saturating_mul_div_ceil(
        i64_to_u64_saturating(cost),
        weight,
        total_weight,
    ))
}

fn apply_lag_feedback(current: i64, expected: i64, actual: i64, window: i64) -> i64 {
    if window <= 0 {
        return 0;
    }
    if expected >= actual {
        return clamp_lag(current.saturating_add(expected - actual), window);
    }
    clamp_lag(current.saturating_sub(actual - expected), window)
}

fn clamp_lag(value: i64, window: i64) -> i64 {
    if window <= 0 {
        return 0;
    }
    let limit = if window <= MAX_SIGNED_I64 / 2 {
        window * 2
    } else {
        MAX_SIGNED_I64
    };
    value.clamp(-limit, limit)
}

fn is_fresh_stream(state: &BatchState, stream_id: u64) -> bool {
    !is_synthetic_stream_key(stream_id)
        && !state.stream_finish_tag.contains_key(&stream_id)
        && !state.stream_last_service.contains_key(&stream_id)
        && !state.stream_lag.contains_key(&stream_id)
}

fn is_fresh_group(state: &BatchState, group_key: GroupKey) -> bool {
    !group_key.is_transient()
        && !state.group_finish_tag.contains_key(&group_key)
        && !state.group_last_service.contains_key(&group_key)
        && !state.group_lag.contains_key(&group_key)
}

fn group_virtual_time(state: &BatchState, group_key: GroupKey) -> u64 {
    state
        .group_virtual_time
        .get(&group_key)
        .copied()
        .unwrap_or(0)
}

fn group_finish_tag(state: &BatchState, group_key: GroupKey) -> u64 {
    state.group_finish_tag.get(&group_key).copied().unwrap_or(0)
}

fn group_last_served(state: &BatchState, group_key: GroupKey) -> u64 {
    state
        .group_last_service
        .get(&group_key)
        .copied()
        .unwrap_or(0)
}

fn stream_finish_tag(state: &BatchState, stream_id: u64) -> u64 {
    state
        .stream_finish_tag
        .get(&stream_id)
        .copied()
        .unwrap_or(0)
}

fn stream_last_served(state: &BatchState, stream_id: u64) -> u64 {
    state
        .stream_last_service
        .get(&stream_id)
        .copied()
        .unwrap_or(0)
}

fn group_lag(state: &BatchState, group_key: GroupKey) -> i64 {
    state.group_lag.get(&group_key).copied().unwrap_or(0)
}

fn stream_lag(state: &BatchState, stream_id: u64) -> i64 {
    state.stream_lag.get(&stream_id).copied().unwrap_or(0)
}

fn maybe_rebase_wfq_state(state: &mut BatchState) {
    if state.root_virtual_time < (1u64 << 48) {
        return;
    }
    let floor = state
        .group_virtual_time
        .values()
        .chain(state.group_finish_tag.values())
        .chain(state.stream_finish_tag.values())
        .fold(state.root_virtual_time, |floor, tag| floor.min(*tag));
    if floor == 0 {
        return;
    }
    state.root_virtual_time = state.root_virtual_time.saturating_sub(floor);
    for tag in state.group_virtual_time.values_mut() {
        *tag = tag.saturating_sub(floor);
    }
    for tag in state.group_finish_tag.values_mut() {
        *tag = tag.saturating_sub(floor);
    }
    for tag in state.stream_finish_tag.values_mut() {
        *tag = tag.saturating_sub(floor);
    }
}

fn saturating_mul_div_ceil(value: u64, multiplier: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return u64::MAX;
    }
    let product = u128::from(value).saturating_mul(u128::from(multiplier));
    u128_to_u64_saturating(product.div_ceil(u128::from(divisor)))
}

fn saturating_mul_div_floor(value: u64, multiplier: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return u64::MAX;
    }
    let product = u128::from(value).saturating_mul(u128::from(multiplier));
    u128_to_u64_saturating(product / u128::from(divisor))
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn i64_to_u64_saturating(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(MAX_SIGNED_I64)
}

fn u128_to_u64_saturating(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_req(stream_id: u64, cost: i64) -> BatchItem {
        BatchItem {
            request: RequestMeta {
                group_key: GroupKey::stream(stream_id),
                stream_id,
                stream_scoped: true,
                cost,
                ..RequestMeta::default()
            },
            stream: StreamMeta::default(),
        }
    }

    fn stream_req_with_priority(stream_id: u64, cost: i64, priority: u64) -> BatchItem {
        BatchItem {
            stream: StreamMeta { priority },
            ..stream_req(stream_id, cost)
        }
    }

    fn session_req(index: usize) -> BatchItem {
        BatchItem {
            request: RequestMeta {
                group_key: GroupKey::transient(index),
                cost: 1,
                ..RequestMeta::default()
            },
            stream: StreamMeta::default(),
        }
    }

    fn stream_ids(items: &[BatchItem], order: &[usize]) -> Vec<u64> {
        order
            .iter()
            .map(|idx| items[*idx].request.stream_id)
            .collect()
    }

    fn urgent_req(index: usize, urgency_rank: i32, stream_id: Option<u64>) -> BatchItem {
        let (stream_scoped, stream_id, group_key) = match stream_id {
            Some(stream_id) => (true, stream_id, GroupKey::stream(stream_id)),
            None => (false, 0, GroupKey::transient(index)),
        };
        BatchItem {
            request: RequestMeta {
                group_key,
                stream_id,
                stream_scoped,
                urgency_rank,
                cost: 1,
                ..RequestMeta::default()
            },
            stream: StreamMeta::default(),
        }
    }

    #[test]
    fn batch_stream_queue_front_consumption_preserves_order_without_shifting_each_pop() {
        let mut queue = BatchStreamQueue::new(7);
        for idx in 0..96 {
            queue.push(idx);
        }

        for expected in 0..64 {
            assert_eq!(queue.pop_front(), Some(expected));
        }
        assert_eq!(queue.pop_front(), Some(64));

        queue.push(200);
        let priority_pos = queue.head + 3;
        assert_eq!(queue.remove(priority_pos), Some(68));

        let remaining: Vec<_> = std::iter::from_fn(|| queue.pop_front()).collect();
        assert_eq!(&remaining[..3], &[65, 66, 67]);
        assert!(!remaining.contains(&68));
        assert_eq!(remaining.last().copied(), Some(200));
    }

    #[test]
    fn stream_candidate_selection_uses_head_offset_for_priority_updates() {
        let mut queue = BatchStreamQueue::new(5);
        for idx in 0..5 {
            queue.push(idx);
        }
        assert_eq!(queue.pop_front(), Some(0));
        assert_eq!(queue.pop_front(), Some(1));

        let mut items = vec![stream_req(5, 1); 5];
        items[4].request.is_priority_update = true;

        let (req_idx, queue_pos, _, is_priority_update) =
            select_stream_candidate(&queue, &items, false).unwrap();
        assert_eq!(req_idx, 4);
        assert_eq!(queue_pos, 4);
        assert!(is_priority_update);

        assert_eq!(queue.remove(queue_pos), Some(4));
        let (req_idx, queue_pos, _, is_priority_update) =
            select_stream_candidate(&queue, &items, false).unwrap();
        assert_eq!(req_idx, 2);
        assert_eq!(queue_pos, queue.head);
        assert!(!is_priority_update);
    }

    fn seed_retained_stream_and_group_state(
        state: &mut BatchState,
        stream_id: u64,
        group: GroupKey,
    ) {
        state.stream_finish_tag.insert(stream_id, 3);
        state.stream_last_service.insert(stream_id, 5);
        state.stream_lag.insert(stream_id, 7);
        state
            .stream_class
            .insert(stream_id, TrafficClass::Interactive);
        state.stream_last_seen_batch.insert(stream_id, 11);
        state.small_burst_disarmed.insert(stream_id, ());
        state
            .group_virtual_time
            .insert(GroupKey::stream(stream_id), 13);
        state.group_virtual_time.insert(group, 17);
        state
            .group_finish_tag
            .insert(GroupKey::stream(stream_id), 19);
        state.group_finish_tag.insert(group, 23);
        state
            .group_last_service
            .insert(GroupKey::stream(stream_id), 29);
        state.group_last_service.insert(group, 31);
        state.group_lag.insert(GroupKey::stream(stream_id), 37);
        state.group_lag.insert(group, 41);
        state
            .preferred_stream_head
            .insert(GroupKey::stream(stream_id), stream_id);
        state.preferred_stream_head.insert(group, stream_id);
    }

    fn assert_retained_stream_and_group_state_dropped(
        state: &BatchState,
        stream_id: u64,
        group: GroupKey,
    ) {
        assert!(!state.stream_finish_tag.contains_key(&stream_id));
        assert!(!state.stream_last_service.contains_key(&stream_id));
        assert!(!state.stream_lag.contains_key(&stream_id));
        assert!(!state.stream_class.contains_key(&stream_id));
        assert!(!state.stream_last_seen_batch.contains_key(&stream_id));
        assert!(!state.small_burst_disarmed.contains_key(&stream_id));
        assert!(!state
            .group_virtual_time
            .contains_key(&GroupKey::stream(stream_id)));
        assert!(!state.group_virtual_time.contains_key(&group));
        assert!(!state
            .group_finish_tag
            .contains_key(&GroupKey::stream(stream_id)));
        assert!(!state.group_finish_tag.contains_key(&group));
        assert!(!state
            .group_last_service
            .contains_key(&GroupKey::stream(stream_id)));
        assert!(!state.group_last_service.contains_key(&group));
        assert!(!state.group_lag.contains_key(&GroupKey::stream(stream_id)));
        assert!(!state.group_lag.contains_key(&group));
        assert!(!state
            .preferred_stream_head
            .contains_key(&GroupKey::stream(stream_id)));
        assert!(!state.preferred_stream_head.contains_key(&group));
    }

    #[test]
    fn clear_drops_retained_scheduler_backings() {
        let mut scheduler = BatchScheduler::default();
        scheduler.state.group_virtual_time = HashMap::with_capacity(2048);
        scheduler.state.stream_finish_tag = HashMap::with_capacity(2048);
        scheduler.state.preferred_stream_head = HashMap::with_capacity(2048);
        scheduler.active_group_refs = HashMap::with_capacity(2048);
        scheduler.stream_group_buckets = HashMap::with_capacity(2048);
        scheduler.stream_group_values = HashMap::with_capacity(2048);

        scheduler
            .state
            .group_virtual_time
            .insert(GroupKey::explicit(7), 1);
        scheduler.state.stream_finish_tag.insert(4, 2);
        scheduler
            .state
            .preferred_stream_head
            .insert(GroupKey::explicit(7), 4);
        scheduler.active_group_refs.insert(7, 1);
        scheduler.stream_group_buckets.insert(4, 7);
        scheduler.stream_group_values.insert(4, 7);
        assert!(scheduler.active_group_refs.capacity() >= 2048);

        scheduler.clear();

        assert_eq!(scheduler.state.group_virtual_time.capacity(), 0);
        assert_eq!(scheduler.state.stream_finish_tag.capacity(), 0);
        assert_eq!(scheduler.state.preferred_stream_head.capacity(), 0);
        assert_eq!(scheduler.active_group_refs.capacity(), 0);
        assert_eq!(scheduler.stream_group_buckets.capacity(), 0);
        assert_eq!(scheduler.stream_group_values.capacity(), 0);
    }

    #[test]
    fn mild_priority_mid_sized_stream_stays_interactive_under_balanced_hint() {
        let quantum = 16_384;

        assert_eq!(
            classify_stream_class(
                quantum + 1,
                1,
                SchedulerHint::UnspecifiedOrBalanced,
                None,
                quantum,
            ),
            TrafficClass::Interactive
        );
        assert_eq!(
            classify_stream_class(quantum + 1, 3, SchedulerHint::BalancedFair, None, quantum, ),
            TrafficClass::Interactive
        );
        assert_eq!(
            classify_stream_class(
                quantum + 1,
                0,
                SchedulerHint::UnspecifiedOrBalanced,
                None,
                quantum,
            ),
            TrafficClass::Bulk
        );
    }

    #[test]
    fn write_burst_limit_tracks_priority_bands_and_latency_hint() {
        assert_eq!(
            write_burst_limit(0, SchedulerHint::UnspecifiedOrBalanced),
            DEFAULT_WRITE_BURST_FRAMES
        );
        assert_eq!(
            write_burst_limit(2, SchedulerHint::UnspecifiedOrBalanced),
            MILD_WRITE_BURST_FRAMES
        );
        assert_eq!(
            write_burst_limit(6, SchedulerHint::UnspecifiedOrBalanced),
            STRONG_WRITE_BURST_FRAMES
        );
        assert_eq!(
            write_burst_limit(20, SchedulerHint::UnspecifiedOrBalanced),
            SATURATED_WRITE_BURST_FRAMES
        );
        assert_eq!(
            write_burst_limit(0, SchedulerHint::Latency),
            MILD_WRITE_BURST_FRAMES
        );
    }

    #[test]
    fn urgent_batch_orders_by_rank_stream_scope_and_stream_id() {
        let items = [
            urgent_req(0, 8, None),
            urgent_req(1, 5, Some(8)),
            urgent_req(2, 5, None),
            urgent_req(3, 2, Some(12)),
            urgent_req(4, 3, Some(4)),
            urgent_req(5, 4, Some(16)),
            urgent_req(6, 1, None),
        ];

        let order = order_urgent_batch(&items);

        assert_eq!(order, vec![6, 3, 4, 5, 1, 2, 0]);
    }

    #[test]
    fn flat_batch_head_rotates_across_batches() {
        let mut scheduler = BatchScheduler::default();
        let items = [stream_req(4, 1), stream_req(8, 1)];
        let cfg = BatchConfig {
            max_frame_payload: 16_384,
            ..BatchConfig::default()
        };

        let first = scheduler.order(cfg, &items);
        let second = scheduler.order(cfg, &items);

        assert_eq!(stream_ids(&items, &first), vec![4, 8]);
        assert_eq!(stream_ids(&items, &second), vec![8, 4]);
    }

    #[test]
    fn higher_priority_stream_leads_ordinary_batch() {
        let mut scheduler = BatchScheduler::default();
        let items = [
            stream_req_with_priority(4, 1, 0),
            stream_req_with_priority(8, 1, 20),
        ];

        let order = scheduler.order(
            BatchConfig {
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &items,
        );

        assert_eq!(stream_ids(&items, &order), vec![8, 4]);
    }

    #[test]
    fn session_scoped_ordinary_does_not_consume_retained_flat_head() {
        let mut scheduler = BatchScheduler::default();
        let seed = [stream_req(4, 1), stream_req(8, 1)];

        let first = scheduler.order(BatchConfig::default(), &seed);

        let mixed = [session_req(0), stream_req(4, 1), stream_req(8, 1)];
        let second = scheduler.order(BatchConfig::default(), &mixed);

        assert_eq!(stream_ids(&seed, &first), vec![4, 8]);
        assert_eq!(stream_ids(&mixed, &second), vec![0, 8, 4]);
    }

    #[test]
    fn transient_session_scoped_ordinary_gets_single_head_before_real_streams() {
        let mut scheduler = BatchScheduler::default();
        let items = [session_req(0), stream_req(4, 5), stream_req(8, 5)];

        let order = scheduler.order(BatchConfig::default(), &items);

        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn session_scoped_ordinary_batch_does_not_erase_retained_real_bias() {
        let mut scheduler = BatchScheduler::default();
        let cfg = BatchConfig {
            max_frame_payload: 16_384,
            ..BatchConfig::default()
        };
        let real = [stream_req(4, 5), stream_req(8, 5)];

        let first = scheduler.order(cfg, &real);
        let session_only = [session_req(0), session_req(1)];
        let session_order = scheduler.order(cfg, &session_only);
        let second = scheduler.order(cfg, &real);

        assert_eq!(stream_ids(&real, &first), vec![4, 8]);
        assert_eq!(session_order, vec![0, 1]);
        assert_eq!(stream_ids(&real, &second), vec![8, 4]);
    }

    #[test]
    fn equal_streams_interleave_within_batch() {
        let mut state = BatchState::default();
        let items = [stream_req(4, 1), stream_req(4, 1), stream_req(8, 1)];

        let order = order_batch_indices(
            BatchConfig {
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &mut state,
            &items,
        );

        assert_eq!(stream_ids(&items, &order), vec![4, 8, 4]);
    }

    #[test]
    fn wfq_clocks_advance_by_active_group_and_stream_weights() {
        let cfg = BatchConfig {
            max_frame_payload: 16_384,
            ..BatchConfig::default()
        };
        let mut flat_state = BatchState::default();
        let flat = [stream_req(4, 1), stream_req(8, 1)];

        let flat_order = order_batch_indices(cfg, &mut flat_state, &flat);

        assert_eq!(stream_ids(&flat, &flat_order), vec![4, 8]);
        assert_eq!(flat_state.root_virtual_time, 11);
        assert_eq!(flat_state.service_seq, 2);

        let group = GroupKey::explicit(7);
        let mut group_state = BatchState::default();
        let grouped = [
            BatchItem {
                request: RequestMeta {
                    group_key: group,
                    stream_id: 4,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: group,
                    stream_id: 8,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let group_order = order_batch_indices(
            BatchConfig {
                scheduler_hint: SchedulerHint::GroupFair,
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &mut group_state,
            &grouped,
        );

        assert_eq!(stream_ids(&grouped, &group_order), vec![4, 8]);
        assert_eq!(group_state.root_virtual_time, 19);
        assert_eq!(group_state.group_virtual_time.get(&group), Some(&6));
    }

    #[test]
    fn session_scoped_head_stays_out_of_wfq_competition() {
        let mut state = BatchState::default();
        let items = [
            session_req(0),
            stream_req_with_priority(4, 40_000, 0),
            stream_req_with_priority(8, 40_000, 20),
        ];

        let order = order_batch_indices(
            BatchConfig {
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &mut state,
            &items,
        );

        assert_eq!(order[0], 0);
        assert_eq!(stream_ids(&items, &order[1..]), vec![8, 4]);
    }

    #[test]
    fn priority_update_gets_one_batch_head_opportunity() {
        let mut scheduler = BatchScheduler::default();
        let items = [
            stream_req(8, 1),
            stream_req(4, 1),
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::stream(4),
                    stream_id: 4,
                    stream_scoped: true,
                    is_priority_update: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let order = scheduler.order(BatchConfig::default(), &items);

        assert_eq!(order[0], 2);
        assert_eq!(stream_ids(&items, &order[1..]), vec![8, 4]);
    }

    #[test]
    fn priority_updates_precede_future_data_for_each_stream() {
        let mut scheduler = BatchScheduler::default();
        let priority_update = |stream_id| BatchItem {
            request: RequestMeta {
                group_key: GroupKey::stream(stream_id),
                stream_id,
                stream_scoped: true,
                is_priority_update: true,
                cost: 1,
                ..RequestMeta::default()
            },
            stream: StreamMeta::default(),
        };
        let items = [
            priority_update(4),
            stream_req(4, 1),
            priority_update(8),
            stream_req(8, 1),
        ];

        let order = scheduler.order(BatchConfig::default(), &items);
        let pos = |idx| order.iter().position(|ordered| *ordered == idx).unwrap();

        assert_eq!(order[0], 0);
        assert!(pos(0) < pos(1));
        assert!(pos(2) < pos(3));
    }

    #[test]
    fn eligible_stream_and_group_precede_lower_finish_ineligible_candidates() {
        let mut stream_state = BatchState::default();
        stream_state
            .group_virtual_time
            .insert(GroupKey::stream(4), 0);
        stream_state
            .group_virtual_time
            .insert(GroupKey::stream(8), 0);
        stream_state.stream_finish_tag.insert(4, 12);
        let streams = [stream_req_with_priority(4, 1, 20), stream_req(8, 8)];

        let stream_order = order_batch_indices(
            BatchConfig {
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &mut stream_state,
            &streams,
        );

        assert_eq!(streams[stream_order[0]].request.stream_id, 8);

        let group_a = GroupKey::explicit(7);
        let group_b = GroupKey::explicit(9);
        let mut group_state = BatchState {
            root_virtual_time: 4,
            ..BatchState::default()
        };
        group_state.group_finish_tag.insert(group_a, 12);
        group_state.group_finish_tag.insert(group_b, 4);
        let groups = [
            BatchItem {
                request: RequestMeta {
                    group_key: group_a,
                    stream_id: 4,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: group_b,
                    stream_id: 8,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let group_order = order_batch_indices(
            BatchConfig {
                scheduler_hint: SchedulerHint::GroupFair,
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &mut group_state,
            &groups,
        );

        assert_eq!(groups[group_order[0]].request.stream_id, 8);
    }

    #[test]
    fn higher_priority_short_flow_leads_bulk_flow() {
        let mut state = BatchState::default();
        let items = [
            stream_req_with_priority(4, 40_000, 0),
            stream_req_with_priority(8, 512, 20),
        ];

        let order = order_batch_indices(
            BatchConfig {
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &mut state,
            &items,
        );

        assert_eq!(items[order[0]].request.stream_id, 8);
    }

    #[test]
    fn group_fair_interleaves_explicit_groups() {
        let mut scheduler = BatchScheduler::default();
        let items = [
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::explicit(7),
                    stream_id: 4,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::explicit(7),
                    stream_id: 8,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::explicit(9),
                    stream_id: 12,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::explicit(9),
                    stream_id: 16,
                    stream_scoped: true,
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let order = scheduler.order(
            BatchConfig {
                scheduler_hint: SchedulerHint::GroupFair,
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &items,
        );

        assert_eq!(stream_ids(&items, &order), vec![4, 12, 8, 16]);

        let second = scheduler.order(
            BatchConfig {
                scheduler_hint: SchedulerHint::GroupFair,
                max_frame_payload: 16_384,
                ..BatchConfig::default()
            },
            &items,
        );

        assert_eq!(stream_ids(&items, &second), vec![16, 8, 12, 4]);
    }

    #[test]
    fn stream_group_tracking_uses_fallback_after_cap() {
        let mut scheduler = BatchScheduler::default();
        for stream_id in 1..=usize_to_u64_saturating(MAX_EXPLICIT_GROUPS) {
            let key = scheduler.group_key_for_stream(stream_id, Some(stream_id), true);
            assert_eq!(key, GroupKey::explicit(stream_id));
        }
        let fallback = scheduler.group_key_for_stream(99, Some(99), true);
        assert_eq!(fallback, GroupKey::explicit(FALLBACK_GROUP_BUCKET));
        assert_eq!(
            scheduler.active_group_refs.get(&FALLBACK_GROUP_BUCKET),
            Some(&1)
        );
        assert_eq!(scheduler.stream_group_values.get(&99), Some(&99));
        assert_eq!(
            scheduler.stream_group_buckets.get(&99),
            Some(&FALLBACK_GROUP_BUCKET)
        );

        scheduler.drop_stream(1);
        let reused = scheduler.group_key_for_stream(100, Some(100), true);
        assert_eq!(reused, GroupKey::explicit(100));
    }

    #[test]
    fn tracked_explicit_group_count_ignores_zero_and_fallback() {
        let mut scheduler = BatchScheduler::default();
        scheduler.active_group_refs.insert(0, 1);
        scheduler.active_group_refs.insert(7, 2);
        scheduler.active_group_refs.insert(9, 1);
        scheduler.active_group_refs.insert(FALLBACK_GROUP_BUCKET, 3);

        assert_eq!(scheduler.tracked_explicit_group_count(), 2);
    }

    #[test]
    fn explicit_group_refcount_counts_past_int_boundary() {
        let mut scheduler = BatchScheduler::default();
        scheduler.active_group_refs.insert(7, i32::MAX as u64);

        let key = scheduler.group_key_for_stream(4, Some(7), true);

        assert_eq!(key, GroupKey::explicit(7));
        assert_eq!(
            scheduler.active_group_refs.get(&7),
            Some(&((i32::MAX as u64) + 1))
        );

        scheduler.drop_stream(4);

        assert_eq!(
            scheduler.active_group_refs.get(&7),
            Some(&(i32::MAX as u64))
        );
    }

    #[test]
    fn group_change_preserves_shared_old_ref_and_drops_last_departure_state() {
        let mut scheduler = BatchScheduler::default();
        let old_group = GroupKey::explicit(7);
        let new_group = GroupKey::explicit(9);
        assert_eq!(scheduler.group_key_for_stream(4, Some(7), true), old_group);
        assert_eq!(scheduler.group_key_for_stream(8, Some(7), true), old_group);
        seed_retained_stream_and_group_state(&mut scheduler.state, 4, old_group);
        scheduler.state.group_virtual_time.insert(new_group, 13);

        assert_eq!(scheduler.group_key_for_stream(4, Some(9), true), new_group);

        assert_eq!(scheduler.active_group_refs.get(&7), Some(&1));
        assert_eq!(scheduler.active_group_refs.get(&9), Some(&1));
        assert!(scheduler.state.group_virtual_time.contains_key(&old_group));
        assert_eq!(scheduler.stream_group_buckets.get(&8), Some(&7));

        assert_eq!(scheduler.group_key_for_stream(8, Some(9), true), new_group);

        assert!(!scheduler.active_group_refs.contains_key(&7));
        assert_eq!(scheduler.active_group_refs.get(&9), Some(&2));
        assert!(!scheduler.state.group_virtual_time.contains_key(&old_group));
        assert!(scheduler.state.group_virtual_time.contains_key(&new_group));
    }

    #[test]
    fn group_reset_to_zero_releases_tracking_and_retained_group_state() {
        let mut scheduler = BatchScheduler::default();
        let old_group = GroupKey::explicit(7);
        assert_eq!(scheduler.group_key_for_stream(4, Some(7), true), old_group);
        scheduler.state.group_virtual_time.insert(old_group, 11);

        assert_eq!(
            scheduler.group_key_for_stream(4, Some(0), true),
            GroupKey::stream(4)
        );

        assert!(!scheduler.active_group_refs.contains_key(&7));
        assert!(!scheduler.stream_group_buckets.contains_key(&4));
        assert!(!scheduler.stream_group_values.contains_key(&4));
        assert!(!scheduler.state.group_virtual_time.contains_key(&old_group));
    }

    #[test]
    fn drop_stream_removes_retained_stream_and_explicit_group_state() {
        let mut scheduler = BatchScheduler::default();
        let group = GroupKey::explicit(7);
        assert_eq!(scheduler.group_key_for_stream(4, Some(7), true), group);
        seed_retained_stream_and_group_state(&mut scheduler.state, 4, group);

        scheduler.drop_stream(4);

        assert!(!scheduler.active_group_refs.contains_key(&7));
        assert_retained_stream_and_group_state_dropped(&scheduler.state, 4, group);
    }

    #[test]
    fn dropped_last_stream_releases_idle_scheduler_state() {
        let mut scheduler = BatchScheduler::default();
        let items = [stream_req(4, 1), stream_req(8, 1)];

        let order = scheduler.order(BatchConfig::default(), &items);
        assert_eq!(order.len(), items.len());
        assert!(scheduler.state.root_virtual_time > 0);

        scheduler.drop_stream(4);
        scheduler.drop_stream(8);

        assert_eq!(scheduler.state.root_virtual_time, 0);
        assert_eq!(scheduler.state.service_seq, 0);
        assert!(scheduler.state.group_virtual_time.is_empty());
        assert!(scheduler.state.group_finish_tag.is_empty());
        assert!(scheduler.state.group_last_service.is_empty());
        assert!(scheduler.state.group_lag.is_empty());
        assert!(scheduler.state.stream_finish_tag.is_empty());
        assert!(scheduler.state.stream_last_service.is_empty());
        assert!(scheduler.state.stream_lag.is_empty());
        assert!(scheduler.state.stream_class.is_empty());
        assert!(scheduler.state.stream_last_seen_batch.is_empty());
        assert!(scheduler.state.small_burst_disarmed.is_empty());
        assert!(scheduler.state.preferred_group_head.is_none());
        assert!(scheduler.state.preferred_stream_head.is_empty());
        assert_eq!(scheduler.state.scratch.groups.capacity(), 0);
        assert_eq!(scheduler.state.scratch.prepared_streams.capacity(), 0);
        assert_eq!(scheduler.state.scratch.selected.capacity(), 0);
        assert_eq!(scheduler.state.scratch.group_indices.capacity(), 0);
    }

    #[test]
    fn session_scoped_only_batch_scrubs_idle_retained_scheduler_state() {
        let mut state = BatchState {
            root_virtual_time: 11,
            service_seq: 7,
            batch_seq: 3,
            interactive_streak: 2,
            class_selections_since_bulk: 1,
            ..BatchState::default()
        };
        state.group_lag.insert(GroupKey::stream(4), 5);
        state.stream_lag.insert(4, 6);
        let items = [session_req(0)];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(order, vec![0]);
        assert_eq!(state.root_virtual_time, 0);
        assert_eq!(state.service_seq, 0);
        assert_eq!(state.batch_seq, 0);
        assert_eq!(state.interactive_streak, 0);
        assert_eq!(state.class_selections_since_bulk, 0);
        assert!(state.group_lag.is_empty());
        assert!(state.stream_lag.is_empty());
    }

    #[test]
    fn single_session_scoped_batch_preserves_retained_real_scheduler_state() {
        let mut state = BatchState::default();
        let group = GroupKey::stream(4);
        seed_retained_stream_and_group_state(&mut state, 4, group);
        state.preferred_group_head = Some(group);
        let items = [session_req(0)];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(order, vec![0]);
        assert!(state.stream_finish_tag.contains_key(&4));
        assert!(state.stream_last_service.contains_key(&4));
        assert!(state.group_finish_tag.contains_key(&group));
        assert!(state.group_last_service.contains_key(&group));
        assert_eq!(state.preferred_group_head, Some(group));
    }

    #[test]
    fn multi_session_scoped_batch_preserves_retained_real_scheduler_state() {
        let mut state = BatchState::default();
        let group = GroupKey::stream(4);
        seed_retained_stream_and_group_state(&mut state, 4, group);
        state.preferred_group_head = Some(group);
        let items = [session_req(0), session_req(1)];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(order, vec![0, 1]);
        assert!(state.stream_finish_tag.contains_key(&4));
        assert!(state.stream_last_service.contains_key(&4));
        assert!(state.group_finish_tag.contains_key(&group));
        assert!(state.group_last_service.contains_key(&group));
        assert_eq!(state.preferred_group_head, Some(group));
    }

    #[test]
    fn single_urgent_batch_preserves_retained_real_scheduler_state() {
        let mut state = BatchState::default();
        let group = GroupKey::stream(4);
        seed_retained_stream_and_group_state(&mut state, 4, group);
        state.preferred_group_head = Some(group);
        let mut item = session_req(0);
        item.request.urgency_rank = 1;
        let items = [item];

        let order = order_batch_indices(
            BatchConfig {
                urgent: true,
                ..BatchConfig::default()
            },
            &mut state,
            &items,
        );

        assert_eq!(order, vec![0]);
        assert!(state.stream_finish_tag.contains_key(&4));
        assert!(state.stream_last_service.contains_key(&4));
        assert!(state.group_finish_tag.contains_key(&group));
        assert!(state.group_last_service.contains_key(&group));
        assert_eq!(state.preferred_group_head, Some(group));
    }

    #[test]
    fn scheduler_extreme_math_saturates_without_wrapping() {
        assert_eq!(
            feedback_window(SchedulerHint::Latency, u64::MAX),
            MAX_SIGNED_I64
        );
        assert!(adjust_weight_for_lag(10, i64::MIN, MAX_SIGNED_I64, false) >= 1);
        assert_eq!(fair_share(MAX_SIGNED_I64, u64::MAX, 1), MAX_SIGNED_I64);
        assert_eq!(saturating_mul_div_ceil(u64::MAX, u64::MAX, 1), u64::MAX);
        assert_eq!(saturating_mul_div_floor(u64::MAX, u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn scheduler_order_into_reuses_caller_storage() {
        let mut scheduler = BatchScheduler::default();
        let items = [stream_req(4, 1), stream_req(8, 1)];
        let mut order = Vec::with_capacity(16);

        scheduler.order_into(BatchConfig::default(), &items, &mut order);
        let retained_capacity = order.capacity();

        assert_eq!(stream_ids(&items, &order), vec![4, 8]);

        scheduler.order_into(BatchConfig::default(), &[session_req(0)], &mut order);

        assert_eq!(order, vec![0]);
        assert_eq!(order.capacity(), retained_capacity);
    }

    #[test]
    fn scratch_reserve_helpers_grow_to_requested_total_capacity() {
        let mut values = Vec::<u8>::with_capacity(8);
        reserve_vec_capacity(&mut values, 32);
        assert!(values.capacity() >= 32);

        let mut map = HashMap::<u8, u8>::with_capacity(8);
        reserve_hashmap_capacity(&mut map, 32);
        assert!(map.capacity() >= 32);
    }

    #[test]
    fn scheduler_weights_follow_hints_and_lag_feedback() {
        let max_payload = 16_384;
        let short_latency = stream_weight(4, 512, SchedulerHint::Latency, max_payload);
        let long_latency = stream_weight(
            4,
            max_payload.saturating_mul(8),
            SchedulerHint::Latency,
            max_payload,
        );
        assert!(short_latency > long_latency);

        let balanced_low = stream_weight(0, max_payload, SchedulerHint::BalancedFair, max_payload);
        let balanced_high =
            stream_weight(20, max_payload, SchedulerHint::BalancedFair, max_payload);
        let bulk_low = stream_weight(0, max_payload, SchedulerHint::BulkThroughput, max_payload);
        let bulk_high = stream_weight(20, max_payload, SchedulerHint::BulkThroughput, max_payload);
        assert!(balanced_high - balanced_low > bulk_high - bulk_low);

        let base = 24;
        let window = feedback_window(SchedulerHint::BalancedFair, max_payload);
        assert!(adjust_weight_for_lag(base, window, window, false) > base);
        assert!(adjust_weight_for_lag(base, 0, window, true) > base);
        let penalized = adjust_weight_for_lag(base, -window, window, false);
        assert!(penalized < base);
        assert!(penalized >= 1);
    }

    #[test]
    fn group_weight_uses_equal_share_for_explicit_groups() {
        assert_eq!(
            group_weight(GroupKey::explicit(7), 96, SchedulerHint::BalancedFair),
            24
        );
        assert_eq!(
            group_weight(GroupKey::stream(4), 96, SchedulerHint::BalancedFair),
            96
        );
    }

    #[test]
    fn scheduler_extreme_lag_math_clamps_without_overflow() {
        let boosted = adjust_weight_for_lag(u64::MAX / 2 + 1, i64::MAX, i64::MAX, false);
        assert_eq!(boosted, u64::MAX);
        assert_eq!(
            service_tag(i64::MAX / 2, WFQ_TAG_SCALE),
            i64_to_u64_saturating(i64::MAX / 2)
        );
        assert_eq!(apply_lag_feedback(i64::MAX - 1, i64::MAX, 0, 10), 20);
        assert_eq!(apply_lag_feedback(-i64::MAX + 1, 0, i64::MAX, 10), -20);
    }

    #[test]
    fn bypass_selection_counters_saturate_and_ignore_synthetic_keys() {
        let mut bypass_selections = HashMap::new();
        let synthetic = SYNTHETIC_STREAM_KEY_BIT | 3;
        bypass_selections.insert(7, usize::MAX);

        update_bypass_selections(&[7, 9, synthetic], 9, &mut bypass_selections);

        assert_eq!(bypass_selections.get(&7), Some(&usize::MAX));
        assert_eq!(bypass_selections.get(&9), Some(&0));
        assert!(!bypass_selections.contains_key(&synthetic));
    }

    #[test]
    fn snapshot_tie_prefs_copies_preferred_stream_heads() {
        let group = GroupKey::explicit(7);
        let mut state = BatchState {
            preferred_group_head: Some(group),
            ..BatchState::default()
        };
        state.preferred_stream_head.insert(group, 4);

        let prefs = snapshot_tie_prefs(&mut state);
        state.preferred_stream_head.insert(group, 8);

        assert_eq!(prefs.group, Some(group));
        assert_eq!(prefs.streams.get(&group), Some(&4));
    }

    #[test]
    fn session_scoped_batch_does_not_retain_synthetic_state() {
        let mut state = BatchState::default();
        let items = [
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::transient(0),
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::transient(1),
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(order, vec![0, 1]);
        assert!(state.stream_finish_tag.is_empty());
        assert!(state.stream_last_service.is_empty());
        assert!(state.stream_lag.is_empty());
        assert!(state.group_finish_tag.is_empty());
        assert!(state.group_last_service.is_empty());
        assert!(state.group_lag.is_empty());
        assert_eq!(state.root_virtual_time, 0);
        assert_eq!(state.service_seq, 0);
        assert!(state.group_virtual_time.is_empty());
        assert!(state.scratch.groups.is_empty());
        assert_eq!(state.scratch.groups.capacity(), 0);
        assert_eq!(state.scratch.prepared_streams.capacity(), 0);
        assert_eq!(state.scratch.selected.capacity(), 0);
    }

    #[test]
    fn mixed_batch_retains_only_real_stream_state() {
        let mut state = BatchState::default();
        let items = [
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::transient(0),
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            stream_req(4, 1),
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::transient(2),
                    cost: 1,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(order, vec![0, 1, 2]);
        assert!(state.stream_finish_tag.contains_key(&4));
        assert!(state
            .stream_finish_tag
            .keys()
            .all(|id| !is_synthetic_stream_key(*id)));
        assert!(state
            .group_finish_tag
            .keys()
            .all(|group| !group.is_transient()));
        assert!(state.group_lag.keys().all(|group| !group.is_transient()));
        assert!(state
            .stream_lag
            .keys()
            .all(|id| !is_synthetic_stream_key(*id)));
    }

    #[test]
    fn build_batch_groups_accumulates_stream_bytes_and_priority_metadata() {
        let mut state = BatchState::default();
        let group_a = GroupKey::explicit(7);
        let group_b = GroupKey::explicit(9);
        let priority = StreamMeta { priority: 9 };
        let items = [
            BatchItem {
                request: RequestMeta {
                    group_key: group_a,
                    stream_id: 4,
                    stream_scoped: true,
                    cost: 2,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: group_a,
                    stream_id: 4,
                    stream_scoped: true,
                    is_priority_update: true,
                    cost: 3,
                    ..RequestMeta::default()
                },
                stream: priority,
            },
            BatchItem {
                request: RequestMeta {
                    group_key: group_b,
                    stream_id: 4,
                    stream_scoped: true,
                    cost: 5,
                    ..RequestMeta::default()
                },
                stream: priority,
            },
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::transient(0),
                    cost: 7,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
        ];

        let prepared = build_batch_groups(&mut state, &items);
        let stream = prepared.prepared_stream(4).unwrap();

        assert!(prepared.has_real_stream_scoped);
        assert!(prepared.has_priority_update);
        assert_eq!(stream.queued_bytes, 10);
        assert_eq!(stream.meta.priority, priority.priority);
    }

    #[test]
    fn fresh_stream_can_beat_stale_preferred_head() {
        let mut state = BatchState::default();
        let stale_group = GroupKey::stream(4);
        state.preferred_group_head = Some(stale_group);
        state.group_virtual_time.insert(stale_group, 0);
        state.group_finish_tag.insert(stale_group, 0);
        state.group_last_service.insert(stale_group, 1);
        state.stream_finish_tag.insert(4, 0);
        state.stream_last_service.insert(4, 1);
        let items = [stream_req(4, 1), stream_req(8, 1)];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(stream_ids(&items, &order), vec![8, 4]);
    }

    #[test]
    fn latency_scheduler_reserves_bulk_opportunity_within_four_selections() {
        let items = [
            stream_req(4, 64),
            stream_req(4, 64),
            stream_req(4, 64),
            stream_req(4, 64),
            stream_req(8, 900),
            stream_req(8, 900),
            stream_req(8, 900),
            stream_req(8, 900),
        ];
        let mut state = BatchState::default();

        let order = order_batch_indices(
            BatchConfig {
                scheduler_hint: SchedulerHint::Latency,
                max_frame_payload: 1_024,
                ..BatchConfig::default()
            },
            &mut state,
            &items,
        );

        let first_four = stream_ids(&items, &order[..4]);
        assert!(first_four.contains(&8));
    }

    #[test]
    fn retained_class_hysteresis_keeps_mid_queue_bulk_across_batches() {
        let mut state = BatchState::default();
        let cfg = BatchConfig {
            scheduler_hint: SchedulerHint::BulkThroughput,
            max_frame_payload: 1_024,
            ..BatchConfig::default()
        };

        let first = [
            stream_req(8, 64),
            stream_req(4, 900),
            stream_req(4, 900),
            stream_req(4, 900),
        ];
        let first_order = order_batch_indices(cfg, &mut state, &first);
        assert_eq!(first_order.len(), first.len());
        assert_eq!(state.stream_class.get(&4), Some(&TrafficClass::Bulk));

        let second = [stream_req(4, 768), stream_req(4, 768), stream_req(8, 64)];
        let second_order = order_batch_indices(cfg, &mut state, &second);

        assert_eq!(second_order.len(), second.len());
        assert_eq!(state.stream_class.get(&4), Some(&TrafficClass::Bulk));
        assert_eq!(state.stream_class.get(&8), Some(&TrafficClass::Interactive));
    }

    #[test]
    fn oversized_scheduler_scratch_is_replaced_after_smaller_batch() {
        let mut state = BatchState::default();
        let oversized = batch_scratch_retain_limit(2).saturating_add(1);
        state.scratch.groups = Vec::with_capacity(oversized);
        state.scratch.group_indices = HashMap::with_capacity(oversized);
        state.scratch.prepared_streams = Vec::with_capacity(oversized);
        state.scratch.prepared_stream_index = HashMap::with_capacity(oversized);
        state.scratch.selected = Vec::with_capacity(oversized);
        state.scratch.bypass_selections = HashMap::with_capacity(oversized);
        state.scratch.recorded_group_head = Vec::with_capacity(oversized);
        state.scratch.interactive_active = Vec::with_capacity(oversized);
        state.scratch.bulk_active = Vec::with_capacity(oversized);
        state.scratch.interactive_candidates = Vec::with_capacity(oversized);
        state.scratch.bulk_candidates = Vec::with_capacity(oversized);
        let first_groups_cap = state.scratch.groups.capacity();
        let first_indices_cap = state.scratch.group_indices.capacity();
        let first_prepared_cap = state.scratch.prepared_streams.capacity();
        let first_prepared_index_cap = state.scratch.prepared_stream_index.capacity();
        let first_selected_cap = state.scratch.selected.capacity();
        let first_bypass_cap = state.scratch.bypass_selections.capacity();
        let first_recorded_cap = state.scratch.recorded_group_head.capacity();
        let first_interactive_cap = state.scratch.interactive_active.capacity();
        let first_bulk_cap = state.scratch.bulk_active.capacity();
        let first_interactive_candidates_cap = state.scratch.interactive_candidates.capacity();
        let first_bulk_candidates_cap = state.scratch.bulk_candidates.capacity();
        let items = [
            stream_req_with_priority(4, 1, 0),
            stream_req_with_priority(8, 1, 20),
        ];

        let order = order_batch_indices(BatchConfig::default(), &mut state, &items);

        assert_eq!(stream_ids(&items, &order), vec![8, 4]);
        assert!(state.scratch.groups.capacity() < first_groups_cap);
        assert!(state.scratch.group_indices.capacity() < first_indices_cap);
        assert!(state.scratch.prepared_streams.capacity() < first_prepared_cap);
        assert!(state.scratch.prepared_stream_index.capacity() < first_prepared_index_cap);
        assert!(state.scratch.selected.capacity() < first_selected_cap);
        assert!(state.scratch.bypass_selections.capacity() < first_bypass_cap);
        assert!(state.scratch.recorded_group_head.capacity() < first_recorded_cap);
        assert!(state.scratch.interactive_active.capacity() < first_interactive_cap);
        assert!(state.scratch.bulk_active.capacity() < first_bulk_cap);
        assert!(state.scratch.interactive_candidates.capacity() < first_interactive_candidates_cap);
        assert!(state.scratch.bulk_candidates.capacity() < first_bulk_candidates_cap);
    }

    #[test]
    fn reusable_scheduler_scratch_does_not_leak_batch_topology() {
        let mut state = BatchState::default();
        let first = [
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::explicit(11),
                    stream_id: 4,
                    stream_scoped: true,
                    cost: 64,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            BatchItem {
                request: RequestMeta {
                    group_key: GroupKey::explicit(22),
                    stream_id: 8,
                    stream_scoped: true,
                    cost: 256,
                    ..RequestMeta::default()
                },
                stream: StreamMeta::default(),
            },
            session_req(2),
        ];
        let first_order = order_batch_indices(
            BatchConfig {
                scheduler_hint: SchedulerHint::GroupFair,
                max_frame_payload: 1_024,
                ..BatchConfig::default()
            },
            &mut state,
            &first,
        );
        assert_eq!(first_order.len(), first.len());

        let second = [stream_req(16, 1), stream_req(32, 1)];
        let second_order = order_batch_indices(BatchConfig::default(), &mut state, &second);

        assert_eq!(stream_ids(&second, &second_order), vec![16, 32]);
    }
}
