//! Compile length ranges into an immutable native-unit policy.

use std::sync::Arc;

use zmux::shaping::{
    Budget, Caps, DatagramPlan, DatagramView, Factory, ProfileLimits, ShapedPipe, Shaper, UnitKind,
    UnitPlan,
};

use crate::{Error, error::err};

/// One half-open range of unpadded encoded unit lengths.
#[derive(Debug, Clone, Copy)]
pub struct Segment {
    /// Unit representation selected by the ordinary scheduler.
    pub kind: UnitKind,
    /// Inclusive lower bound.
    pub lo: usize,
    /// Exclusive upper bound.
    pub hi: usize,
    /// Layout and release request in this range.
    pub plan: UnitPlan,
}

/// An installed profile and its validated native-unit plan table.
#[derive(Debug, Clone)]
pub struct SegmentProfile {
    budget: Budget,
    segments: Arc<[Segment]>,
}

impl SegmentProfile {
    /// Compiles version 1 length ranges before a policy is published.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions and unit kinds, invalid bounds and
    /// unordered, overlapping or unrepresentable ranges.
    pub fn compile(version: u32, budget: Budget, segments: Vec<Segment>) -> Result<Self, Error> {
        if version != 1 {
            return Err(err("unsupported_version", "segment table"));
        }
        budget.validate().map_err(|e| err("range", e.to_string()))?;
        let max = usize::try_from(zmux::proto::record::ZMUX_MAX_RECORD_SIZE + 8)
            .map_err(|_| err("range", "native length is unrepresentable"))?;
        let mut end = 0;
        for segment in &segments {
            if segment.kind != UnitKind::NativeDatagram {
                return Err(err("unsupported_capability", "segment unit kind"));
            }
            if segment.lo < end
                || segment.hi <= segment.lo
                || segment.hi > max + 1
                || segment.plan.pad_to > max
                || segment.plan.pad_multiple > max
                || segment.plan.pad > max
                || segment.plan.delay > std::time::Duration::from_secs(1_000_000_000)
            {
                return Err(err("range", "unrepresentable or overlapping segment"));
            }
            end = segment.hi;
        }
        Ok(Self {
            budget,
            segments: segments.into(),
        })
    }

    /// Effective profile for this policy without a local cap.
    #[must_use]
    pub fn limits(&self) -> ProfileLimits {
        self.budget.profile.unwrap_or(ProfileLimits::LIGHTWEIGHT)
    }

    /// The budget to publish together with this factory.
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// The compiled plan for one encoded native size, or baseline in a gap.
    #[must_use]
    pub fn native_plan(&self, len: usize) -> UnitPlan {
        let index = self.segments.partition_point(|segment| segment.hi <= len);
        self.segments
            .get(index)
            .filter(|segment| segment.lo <= len)
            .map_or_else(UnitPlan::default, |segment| segment.plan)
    }
}

impl Factory for SegmentProfile {
    fn shaper(&self, _: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        Some(Box::new(self.clone()))
    }
}

impl Shaper for SegmentProfile {
    fn capabilities(&self) -> Caps {
        Caps::DATAGRAM_PLAN
    }

    fn plan_datagram(&mut self, view: &DatagramView, plan: &mut DatagramPlan) {
        plan.unit = self.native_plan(view.len);
    }
}
