use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParseConformanceError {
    Claim,
    Profile,
    Suite,
}

impl fmt::Display for ParseConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Claim => "unknown zmux conformance claim",
            Self::Profile => "unknown zmux implementation profile",
            Self::Suite => "unknown zmux conformance suite",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ParseConformanceError {}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Claim {
    WireV1,
    ApiSemanticsProfileV1,
    StreamAdapterProfileV1,
    OpenMetadata,
    PriorityUpdate,
}

impl Claim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WireV1 => "zmux-wire-v1",
            Self::ApiSemanticsProfileV1 => "zmux-api-semantics-profile-v1",
            Self::StreamAdapterProfileV1 => "zmux-stream-adapter-profile-v1",
            Self::OpenMetadata => "zmux-open_metadata",
            Self::PriorityUpdate => "zmux-priority_update",
        }
    }

    pub fn acceptance_checklist(self) -> &'static [&'static str] {
        match self {
            Self::WireV1 => &[
                "pass core wire interoperability",
                "pass invalid-input handling",
                "pass extension-tolerance behavior",
            ],
            Self::OpenMetadata => &[
                "satisfy zmux-wire-v1",
                "negotiate open_metadata",
                "accept valid DATA|OPEN_METADATA on first opening DATA",
                "reject unnegotiated or misplaced OPEN_METADATA",
                "ignore unknown metadata TLVs",
                "drop duplicate singleton metadata while preserving the enclosing DATA",
            ],
            Self::PriorityUpdate => &[
                "satisfy zmux-wire-v1",
                "negotiate priority_update",
                "process stream_priority and stream_group",
                "ignore open_info inside PRIORITY_UPDATE",
                "ignore unknown advisory TLVs",
                "ignore duplicate singleton advisory updates as one dropped update",
            ],
            Self::ApiSemanticsProfileV1 => &[
                "document and implement the repository-default semantic operation families from API_SEMANTICS.md, including full local close helper, graceful send-half completion, read-side stop, send-side reset, whole-stream abort, structured error surfacing, open/cancel behavior, and accept visibility rules",
                "document whether the binding exposes a stream-style convenience profile, a full-control protocol surface, or both",
                "exact API spellings are not required",
            ],
            Self::StreamAdapterProfileV1 => &[
                "satisfy the stream-adapter subset from API_SEMANTICS.md, including bidirectional/unidirectional open and accept mapping",
                "provide one consistent convenience mapping or fuller documented control layer or both",
                "document limits/non-goals",
            ],
        }
    }

    pub fn required_conformance_suites(self) -> &'static [ConformanceSuite] {
        match self {
            Self::WireV1 => &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
            ],
            Self::OpenMetadata => &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
                ConformanceSuite::OpenMetadata,
            ],
            Self::PriorityUpdate => &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
                ConformanceSuite::PriorityUpdate,
            ],
            Self::ApiSemanticsProfileV1 => &[ConformanceSuite::ApiSemanticsProfile],
            Self::StreamAdapterProfileV1 => &[ConformanceSuite::StreamAdapterProfile],
        }
    }
}

impl fmt::Display for Claim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Claim {
    type Err = ParseConformanceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "zmux-wire-v1" => Ok(Self::WireV1),
            "zmux-api-semantics-profile-v1" => Ok(Self::ApiSemanticsProfileV1),
            "zmux-stream-adapter-profile-v1" => Ok(Self::StreamAdapterProfileV1),
            "zmux-open_metadata" => Ok(Self::OpenMetadata),
            "zmux-priority_update" => Ok(Self::PriorityUpdate),
            _ => Err(ParseConformanceError::Claim),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImplementationProfile {
    V1,
    ReferenceProfileV1,
}

impl ImplementationProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "zmux-v1",
            Self::ReferenceProfileV1 => "zmux-reference-profile-v1",
        }
    }

    pub fn claims(self) -> &'static [Claim] {
        match self {
            Self::V1 => &[Claim::WireV1, Claim::OpenMetadata, Claim::PriorityUpdate],
            Self::ReferenceProfileV1 => &[
                Claim::WireV1,
                Claim::ApiSemanticsProfileV1,
                Claim::StreamAdapterProfileV1,
                Claim::OpenMetadata,
                Claim::PriorityUpdate,
            ],
        }
    }

    pub fn acceptance_checklist(self) -> &'static [&'static str] {
        match self {
            Self::V1 => &[
                "satisfy zmux-wire-v1",
                "interoperate on explicit-role and role=auto establishment",
                "pass core stream-lifecycle scenarios",
                "pass core flow-control scenarios",
                "pass core session-lifecycle scenarios",
                "satisfy every currently active same-version optional surface in this repository",
                "negotiate and handle open_metadata, priority_update, priority_hints, and stream_groups correctly",
            ],
            Self::ReferenceProfileV1 => &[
                "satisfy zmux-v1",
                "satisfy the repository-defined reference-profile claim gate",
                "preserve the documented repository-default sender, memory, liveness, API, and scheduling behavior closely enough for release claims",
            ],
        }
    }

    pub fn required_conformance_suites(self) -> &'static [ConformanceSuite] {
        match self {
            Self::V1 => &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
                ConformanceSuite::CoreStreamLifecycle,
                ConformanceSuite::CoreFlowControl,
                ConformanceSuite::CoreSessionLifecycle,
                ConformanceSuite::OpenMetadata,
                ConformanceSuite::PriorityUpdate,
                ConformanceSuite::PriorityHintsAndStreamGroups,
                ConformanceSuite::V1ProfileCompatibility,
            ],
            Self::ReferenceProfileV1 => &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
                ConformanceSuite::CoreStreamLifecycle,
                ConformanceSuite::CoreFlowControl,
                ConformanceSuite::CoreSessionLifecycle,
                ConformanceSuite::OpenMetadata,
                ConformanceSuite::PriorityUpdate,
                ConformanceSuite::PriorityHintsAndStreamGroups,
                ConformanceSuite::V1ProfileCompatibility,
                ConformanceSuite::ApiSemanticsProfile,
                ConformanceSuite::StreamAdapterProfile,
                ConformanceSuite::ReferenceProfileClaimGate,
                ConformanceSuite::ReferenceQualityBehaviors,
            ],
        }
    }

    pub fn release_certification_gate(self) -> &'static [ConformanceSuite] {
        self.required_conformance_suites()
    }
}

impl fmt::Display for ImplementationProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ImplementationProfile {
    type Err = ParseConformanceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "zmux-v1" => Ok(Self::V1),
            "zmux-reference-profile-v1" => Ok(Self::ReferenceProfileV1),
            _ => Err(ParseConformanceError::Profile),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConformanceSuite {
    CoreWireInteroperability,
    InvalidInputHandling,
    ExtensionTolerance,
    CoreStreamLifecycle,
    CoreFlowControl,
    CoreSessionLifecycle,
    OpenMetadata,
    PriorityUpdate,
    PriorityHintsAndStreamGroups,
    V1ProfileCompatibility,
    ApiSemanticsProfile,
    StreamAdapterProfile,
    ReferenceProfileClaimGate,
    ReferenceQualityBehaviors,
}

impl ConformanceSuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoreWireInteroperability => "core-wire-interoperability",
            Self::InvalidInputHandling => "invalid-input-handling",
            Self::ExtensionTolerance => "extension-tolerance",
            Self::CoreStreamLifecycle => "core-stream-lifecycle",
            Self::CoreFlowControl => "core-flow-control",
            Self::CoreSessionLifecycle => "core-session-lifecycle",
            Self::OpenMetadata => "open_metadata",
            Self::PriorityUpdate => "priority_update",
            Self::PriorityHintsAndStreamGroups => "priority-hints-and-stream-groups",
            Self::V1ProfileCompatibility => "v1-profile-compatibility",
            Self::ApiSemanticsProfile => "api-semantics-profile",
            Self::StreamAdapterProfile => "stream-adapter-profile",
            Self::ReferenceProfileClaimGate => "reference-profile-claim-gate",
            Self::ReferenceQualityBehaviors => "reference-quality-behaviors",
        }
    }
}

impl fmt::Display for ConformanceSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ConformanceSuite {
    type Err = ParseConformanceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "core-wire-interoperability" => Ok(Self::CoreWireInteroperability),
            "invalid-input-handling" => Ok(Self::InvalidInputHandling),
            "extension-tolerance" => Ok(Self::ExtensionTolerance),
            "core-stream-lifecycle" => Ok(Self::CoreStreamLifecycle),
            "core-flow-control" => Ok(Self::CoreFlowControl),
            "core-session-lifecycle" => Ok(Self::CoreSessionLifecycle),
            "open_metadata" => Ok(Self::OpenMetadata),
            "priority_update" => Ok(Self::PriorityUpdate),
            "priority-hints-and-stream-groups" => Ok(Self::PriorityHintsAndStreamGroups),
            "v1-profile-compatibility" => Ok(Self::V1ProfileCompatibility),
            "api-semantics-profile" => Ok(Self::ApiSemanticsProfile),
            "stream-adapter-profile" => Ok(Self::StreamAdapterProfile),
            "reference-profile-claim-gate" => Ok(Self::ReferenceProfileClaimGate),
            "reference-quality-behaviors" => Ok(Self::ReferenceQualityBehaviors),
            _ => Err(ParseConformanceError::Suite),
        }
    }
}

pub fn known_claims() -> &'static [Claim] {
    &[
        Claim::WireV1,
        Claim::ApiSemanticsProfileV1,
        Claim::StreamAdapterProfileV1,
        Claim::OpenMetadata,
        Claim::PriorityUpdate,
    ]
}

pub fn known_implementation_profiles() -> &'static [ImplementationProfile] {
    &[
        ImplementationProfile::V1,
        ImplementationProfile::ReferenceProfileV1,
    ]
}

pub fn known_conformance_suites() -> &'static [ConformanceSuite] {
    &[
        ConformanceSuite::CoreWireInteroperability,
        ConformanceSuite::InvalidInputHandling,
        ConformanceSuite::ExtensionTolerance,
        ConformanceSuite::CoreStreamLifecycle,
        ConformanceSuite::CoreFlowControl,
        ConformanceSuite::CoreSessionLifecycle,
        ConformanceSuite::OpenMetadata,
        ConformanceSuite::PriorityUpdate,
        ConformanceSuite::PriorityHintsAndStreamGroups,
        ConformanceSuite::V1ProfileCompatibility,
        ConformanceSuite::ApiSemanticsProfile,
        ConformanceSuite::StreamAdapterProfile,
        ConformanceSuite::ReferenceProfileClaimGate,
        ConformanceSuite::ReferenceQualityBehaviors,
    ]
}

pub fn reference_profile_claim_gate() -> &'static [&'static str] {
    &[
        "repository-default stream-style CloseRead() emits STOP_SENDING(CANCELLED) when that convenience profile is exposed, while fuller control surfaces MAY additionally expose caller-selected codes and diagnostics for STOP_SENDING, RESET, and ABORT",
        "repository-default Close() acts as a full local close helper",
        "repository-default Close() on a unidirectional stream silently ignores the locally absent direction rather than failing solely because that half does not exist",
        "each exposed API surface keeps one documented primary spelling per operation family, with any extra convenience spellings documented as wrappers over the same semantic action rather than as distinct lifecycle operations",
        "before session-ready, repository-default sender behavior emits only the local preface and a fatal establishment CLOSE, and emits none of new-stream DATA, stream-scoped control, ordinary session-scoped control, or EXT",
        "repository-default sender and receiver memory rules enforce the documented hidden-state, provisional-open, and late-tail bounds",
        "repository-default liveness rules keep at most one outstanding protocol PING and do not treat weak local signals as strong progress",
    ]
}

pub fn core_module_target_claims() -> &'static [Claim] {
    &[
        Claim::WireV1,
        Claim::ApiSemanticsProfileV1,
        Claim::OpenMetadata,
        Claim::PriorityUpdate,
    ]
}

pub fn core_module_target_implementation_profiles() -> &'static [ImplementationProfile] {
    &[ImplementationProfile::V1]
}

pub fn core_module_target_suites() -> &'static [ConformanceSuite] {
    &[
        ConformanceSuite::CoreWireInteroperability,
        ConformanceSuite::InvalidInputHandling,
        ConformanceSuite::ExtensionTolerance,
        ConformanceSuite::CoreStreamLifecycle,
        ConformanceSuite::CoreFlowControl,
        ConformanceSuite::CoreSessionLifecycle,
        ConformanceSuite::OpenMetadata,
        ConformanceSuite::PriorityUpdate,
        ConformanceSuite::PriorityHintsAndStreamGroups,
        ConformanceSuite::V1ProfileCompatibility,
        ConformanceSuite::ApiSemanticsProfile,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    #[test]
    fn known_repository_names_match_spec_and_go_registry() {
        assert_eq!(
            known_claims(),
            &[
                Claim::WireV1,
                Claim::ApiSemanticsProfileV1,
                Claim::StreamAdapterProfileV1,
                Claim::OpenMetadata,
                Claim::PriorityUpdate,
            ]
        );
        assert_eq!(
            known_implementation_profiles(),
            &[
                ImplementationProfile::V1,
                ImplementationProfile::ReferenceProfileV1,
            ]
        );
        assert_eq!(
            known_conformance_suites(),
            &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
                ConformanceSuite::CoreStreamLifecycle,
                ConformanceSuite::CoreFlowControl,
                ConformanceSuite::CoreSessionLifecycle,
                ConformanceSuite::OpenMetadata,
                ConformanceSuite::PriorityUpdate,
                ConformanceSuite::PriorityHintsAndStreamGroups,
                ConformanceSuite::V1ProfileCompatibility,
                ConformanceSuite::ApiSemanticsProfile,
                ConformanceSuite::StreamAdapterProfile,
                ConformanceSuite::ReferenceProfileClaimGate,
                ConformanceSuite::ReferenceQualityBehaviors,
            ]
        );
    }

    #[test]
    fn implementation_profiles_expose_repository_claim_bundles_and_suites() {
        assert_eq!(
            ImplementationProfile::V1.claims(),
            &[Claim::WireV1, Claim::OpenMetadata, Claim::PriorityUpdate]
        );
        assert_eq!(
            ImplementationProfile::ReferenceProfileV1.claims(),
            &[
                Claim::WireV1,
                Claim::ApiSemanticsProfileV1,
                Claim::StreamAdapterProfileV1,
                Claim::OpenMetadata,
                Claim::PriorityUpdate,
            ]
        );
        assert_eq!(
            ImplementationProfile::ReferenceProfileV1.required_conformance_suites(),
            ImplementationProfile::ReferenceProfileV1.release_certification_gate()
        );
    }

    #[test]
    fn core_module_publishes_documented_claim_targets_and_v1_profile() {
        assert_eq!(
            core_module_target_claims(),
            &[
                Claim::WireV1,
                Claim::ApiSemanticsProfileV1,
                Claim::OpenMetadata,
                Claim::PriorityUpdate,
            ]
        );
        assert_eq!(
            core_module_target_implementation_profiles(),
            &[ImplementationProfile::V1]
        );
        assert_eq!(
            core_module_target_suites(),
            &[
                ConformanceSuite::CoreWireInteroperability,
                ConformanceSuite::InvalidInputHandling,
                ConformanceSuite::ExtensionTolerance,
                ConformanceSuite::CoreStreamLifecycle,
                ConformanceSuite::CoreFlowControl,
                ConformanceSuite::CoreSessionLifecycle,
                ConformanceSuite::OpenMetadata,
                ConformanceSuite::PriorityUpdate,
                ConformanceSuite::PriorityHintsAndStreamGroups,
                ConformanceSuite::V1ProfileCompatibility,
                ConformanceSuite::ApiSemanticsProfile,
            ]
        );
    }

    #[test]
    fn conformance_names_round_trip_through_lookup_apis() {
        assert_eq!(
            "zmux-priority_update".parse::<Claim>(),
            Ok(Claim::PriorityUpdate)
        );
        assert_eq!(
            "zmux-v1".parse::<ImplementationProfile>(),
            Ok(ImplementationProfile::V1)
        );
        assert_eq!(
            "zmux-reference-profile-v1".parse::<ImplementationProfile>(),
            Ok(ImplementationProfile::ReferenceProfileV1)
        );
        assert_eq!(
            "v1-profile-compatibility".parse::<ConformanceSuite>(),
            Ok(ConformanceSuite::V1ProfileCompatibility)
        );
        assert_eq!(
            reference_profile_claim_gate(),
            &[
                "repository-default stream-style CloseRead() emits STOP_SENDING(CANCELLED) when that convenience profile is exposed, while fuller control surfaces MAY additionally expose caller-selected codes and diagnostics for STOP_SENDING, RESET, and ABORT",
                "repository-default Close() acts as a full local close helper",
                "repository-default Close() on a unidirectional stream silently ignores the locally absent direction rather than failing solely because that half does not exist",
                "each exposed API surface keeps one documented primary spelling per operation family, with any extra convenience spellings documented as wrappers over the same semantic action rather than as distinct lifecycle operations",
                "before session-ready, repository-default sender behavior emits only the local preface and a fatal establishment CLOSE, and emits none of new-stream DATA, stream-scoped control, ordinary session-scoped control, or EXT",
                "repository-default sender and receiver memory rules enforce the documented hidden-state, provisional-open, and late-tail bounds",
                "repository-default liveness rules keep at most one outstanding protocol PING and do not treat weak local signals as strong progress",
            ]
        );
    }

    #[test]
    fn conformance_names_match_repository_claims() {
        assert_eq!(Claim::WireV1.as_str(), "zmux-wire-v1");
        assert_eq!(
            "zmux-reference-profile-v1".parse::<ImplementationProfile>(),
            Ok(ImplementationProfile::ReferenceProfileV1)
        );
        assert_eq!(
            "priority-hints-and-stream-groups".parse::<ConformanceSuite>(),
            Ok(ConformanceSuite::PriorityHintsAndStreamGroups)
        );
    }

    #[test]
    fn reference_profile_contains_reference_only_suites() {
        let suites = ImplementationProfile::ReferenceProfileV1.required_conformance_suites();
        assert!(suites.contains(&ConformanceSuite::ApiSemanticsProfile));
        assert!(suites.contains(&ConformanceSuite::StreamAdapterProfile));
        assert!(suites.contains(&ConformanceSuite::ReferenceProfileClaimGate));
        assert!(suites.contains(&ConformanceSuite::ReferenceQualityBehaviors));
    }

    #[test]
    fn conformance_parse_errors_are_typed() {
        assert_eq!(
            "unknown".parse::<Claim>(),
            Err(ParseConformanceError::Claim)
        );
        assert_eq!(
            "unknown".parse::<ImplementationProfile>(),
            Err(ParseConformanceError::Profile)
        );
        assert_eq!(
            "unknown".parse::<ConformanceSuite>(),
            Err(ParseConformanceError::Suite)
        );
        assert_eq!(
            ParseConformanceError::Claim.to_string(),
            "unknown zmux conformance claim"
        );
    }

    #[test]
    fn core_module_target_suites_are_ordered_union_of_targets() {
        let mut expected = Vec::new();
        for claim in core_module_target_claims() {
            push_unique(&mut expected, claim.required_conformance_suites());
        }
        for profile in core_module_target_implementation_profiles() {
            push_unique(&mut expected, profile.required_conformance_suites());
        }
        expected.retain(|suite| known_conformance_suites().contains(suite));
        expected.sort_by_key(|suite| {
            known_conformance_suites()
                .iter()
                .position(|known| known == suite)
                .unwrap()
        });
        assert_eq!(core_module_target_suites(), expected.as_slice());
    }

    #[test]
    fn conformance_checklist_evidence_covers_claim_and_profile_items() {
        let evidence = conformance_checklist_evidence();

        for item in conformance_checklist_items() {
            let Some(tests) = evidence.get(item) else {
                panic!("missing conformance evidence for checklist item {item:?}");
            };
            assert!(
                !tests.is_empty(),
                "empty conformance evidence for checklist item {item:?}"
            );
        }
    }

    #[test]
    fn conformance_checklist_evidence_references_existing_integration_tests() {
        let test_names = collect_integration_test_names();

        for (item, tests) in conformance_checklist_evidence() {
            for test in tests {
                assert!(
                    test_names.contains(test),
                    "checklist item {item:?} references missing integration test {test}"
                );
            }
        }
    }

    fn conformance_checklist_items() -> BTreeSet<&'static str> {
        let mut items = BTreeSet::new();
        for claim in known_claims() {
            items.extend(claim.acceptance_checklist());
        }
        for profile in known_implementation_profiles() {
            items.extend(profile.acceptance_checklist());
        }
        items.extend(reference_profile_claim_gate());
        items
    }

    fn conformance_checklist_evidence() -> BTreeMap<&'static str, Vec<&'static str>> {
        let mut evidence = BTreeMap::new();
        let wire = Claim::WireV1.acceptance_checklist();
        let open_metadata = Claim::OpenMetadata.acceptance_checklist();
        let priority_update = Claim::PriorityUpdate.acceptance_checklist();
        let api = Claim::ApiSemanticsProfileV1.acceptance_checklist();
        let adapter = Claim::StreamAdapterProfileV1.acceptance_checklist();
        let v1 = ImplementationProfile::V1.acceptance_checklist();
        let reference = ImplementationProfile::ReferenceProfileV1.acceptance_checklist();
        let gate = reference_profile_claim_gate();

        evidence.insert(
            wire[0],
            vec![
                "wire_valid_fixtures_decode_and_round_trip",
                "bidirectional_stream_round_trip_over_memory_transport",
            ],
        );
        evidence.insert(
            wire[1],
            vec![
                "wire_invalid_fixtures_are_rejected",
                "direct_frame_read_rejects_invalid_frame_scopes_and_ext_subtypes",
            ],
        );
        evidence.insert(
            wire[2],
            vec![
                "open_metadata_parser_ignores_unknown_metadata_tlvs",
                "priority_update_parser_ignores_unknown_advisory_tlvs",
                "duplicate_metadata_singletons_short_circuit_later_bad_tlvs",
            ],
        );

        evidence.insert(
            open_metadata[0],
            vec!["wire_valid_fixtures_decode_and_round_trip"],
        );
        evidence.insert(
            open_metadata[1],
            vec!["pre_open_open_metadata_updates_merge_partial_fields"],
        );
        evidence.insert(
            open_metadata[2],
            vec!["open_metadata_preserves_explicit_group_zero_when_rebuilt"],
        );
        evidence.insert(
            open_metadata[3],
            vec![
                "unnegotiated_open_metadata_emits_fatal_close",
                "open_metadata_on_existing_local_stream_fails_session",
            ],
        );
        evidence.insert(
            open_metadata[4],
            vec!["open_metadata_parser_ignores_unknown_metadata_tlvs"],
        );
        evidence.insert(
            open_metadata[5],
            vec!["duplicate_metadata_singletons_short_circuit_later_bad_tlvs"],
        );

        evidence.insert(
            priority_update[0],
            vec!["wire_valid_fixtures_decode_and_round_trip"],
        );
        evidence.insert(
            priority_update[1],
            vec!["inbound_partial_priority_updates_preserve_unspecified_fields"],
        );
        evidence.insert(
            priority_update[2],
            vec!["inbound_partial_priority_updates_preserve_unspecified_fields"],
        );
        evidence.insert(
            priority_update[3],
            vec!["priority_update_parser_ignores_open_info_and_rejects_duplicates"],
        );
        evidence.insert(
            priority_update[4],
            vec!["priority_update_parser_ignores_unknown_advisory_tlvs"],
        );
        evidence.insert(
            priority_update[5],
            vec!["priority_update_parser_ignores_open_info_and_rejects_duplicates"],
        );

        evidence.insert(
            api[0],
            vec![
                "close_read_retry_after_deadline_failure_queues_opener_and_stop_sending",
                "close_with_error_queues_abort_despite_tiny_writer_queue",
                "stream_application_errors_expose_code_and_reason",
                "provisional_open_limit_is_enforced_without_consuming_id",
                "native_stream_direction_queries_match_public_surface",
            ],
        );
        evidence.insert(
            api[1],
            vec![
                "session_trait_object_exposes_timeout_and_open_info_inspection",
                "native_stream_direction_queries_match_public_surface",
                "public_protocol_aliases_remain_pinned",
            ],
        );
        evidence.insert(
            api[2],
            vec![
                "session_trait_object_exposes_timeout_and_open_info_inspection",
                "public_protocol_aliases_remain_pinned",
            ],
        );

        evidence.insert(
            adapter[0],
            vec![
                "session_trait_object_exposes_timeout_and_open_info_inspection",
                "bidirectional_stream_round_trip_over_memory_transport",
            ],
        );
        evidence.insert(
            adapter[1],
            vec![
                "session_trait_object_exposes_timeout_and_open_info_inspection",
                "native_stream_direction_queries_match_public_surface",
            ],
        );
        evidence.insert(
            adapter[2],
            vec!["uni_stream_close_helpers_ignore_absent_directions"],
        );

        evidence.insert(
            v1[0],
            vec![
                "wire_valid_fixtures_decode_and_round_trip",
                "bidirectional_stream_round_trip_over_memory_transport",
                "pre_open_open_metadata_updates_merge_partial_fields",
                "inbound_partial_priority_updates_preserve_unspecified_fields",
            ],
        );
        evidence.insert(
            v1[1],
            vec![
                "role_resolution_and_settings_validation",
                "tcp_constructors_establish_session_with_deadline_control",
            ],
        );
        evidence.insert(
            v1[2],
            vec![
                "bidirectional_stream_round_trip_over_memory_transport",
                "terminal_fin_stream_uses_tombstone_for_late_data",
                "peer_incoming_stream_limit_counts_uncommitted_local_provisionals",
            ],
        );
        evidence.insert(
            v1[3],
            vec![
                "receive_window_replenishes_after_application_read_not_arrival",
                "blocked_write_emits_session_and_stream_blocked_signals",
            ],
        );
        evidence.insert(
            v1[4],
            vec![
                "graceful_close_sends_final_goaway_before_close",
                "peer_close_error_preserves_code_and_reason",
                "keepalive_sends_idle_ping_and_records_rtt",
            ],
        );
        evidence.insert(
            v1[5],
            vec![
                "pre_open_open_metadata_updates_merge_partial_fields",
                "inbound_partial_priority_updates_preserve_unspecified_fields",
            ],
        );
        evidence.insert(
            v1[6],
            vec![
                "pre_open_open_metadata_updates_merge_partial_fields",
                "inbound_partial_priority_updates_preserve_unspecified_fields",
            ],
        );

        evidence.insert(reference[0], evidence[v1[0]].clone());
        evidence.insert(
            reference[1],
            vec!["close_read_retry_after_deadline_failure_queues_opener_and_stop_sending"],
        );
        evidence.insert(
            reference[2],
            vec![
                "close_read_retry_after_deadline_failure_queues_opener_and_stop_sending",
                "rapid_stream_flow_control_aborts_trip_visible_terminal_churn_budget",
                "event_handler_reports_stream_and_session_lifecycle",
                "latency_hint_shrinks_default_write_fragments",
                "keepalive_sends_idle_ping_and_records_rtt",
            ],
        );

        evidence.insert(
            gate[0],
            vec!["close_read_retry_after_deadline_failure_queues_opener_and_stop_sending"],
        );
        evidence.insert(
            gate[1],
            vec![
                "close_with_error_queues_abort_despite_tiny_writer_queue",
                "close_without_graceful_pending_work_sends_direct_close",
            ],
        );
        evidence.insert(
            gate[2],
            vec!["uni_stream_close_helpers_ignore_absent_directions"],
        );
        evidence.insert(
            gate[3],
            vec![
                "session_trait_object_exposes_timeout_and_open_info_inspection",
                "native_stream_direction_queries_match_public_surface",
                "public_protocol_aliases_remain_pinned",
            ],
        );
        evidence.insert(
            gate[4],
            vec![
                "failed_establishment_emits_fatal_close_after_local_preface",
                "same_role_establishment_conflict_emits_role_conflict_close",
            ],
        );
        evidence.insert(
            gate[5],
            vec![
                "rapid_stream_flow_control_aborts_trip_visible_terminal_churn_budget",
                "provisional_open_limit_is_enforced_without_consuming_id",
                "terminal_fin_stream_uses_tombstone_for_late_data",
            ],
        );
        evidence.insert(
            gate[6],
            vec![
                "keepalive_sends_idle_ping_and_records_rtt",
                "ping_rejects_payload_over_default_control_limit_without_queueing",
                "ping_accepts_payload_at_negotiated_control_limit",
            ],
        );

        evidence
    }

    fn collect_integration_test_names() -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for entry in fs::read_dir("tests").expect("tests directory") {
            let path = entry.expect("test file entry").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let content = fs::read_to_string(&path).expect("read integration test file");
            let mut saw_test_attr = false;
            for line in content.lines() {
                let line = line.trim_start();
                if line.starts_with("#[test]") {
                    saw_test_attr = true;
                    continue;
                }
                if saw_test_attr {
                    if let Some(rest) = line.strip_prefix("fn ") {
                        if let Some((name, _)) = rest.split_once('(') {
                            names.insert(name.trim().to_owned());
                        }
                    }
                    if !line.starts_with("#[") && !line.is_empty() {
                        saw_test_attr = false;
                    }
                }
            }
        }
        names
    }

    fn push_unique(out: &mut Vec<ConformanceSuite>, suites: &[ConformanceSuite]) {
        for suite in suites {
            if !out.contains(suite) {
                out.push(*suite);
            }
        }
    }

    #[test]
    fn conformance_checklists_match_spec_text() {
        assert_eq!(
            Claim::ApiSemanticsProfileV1.acceptance_checklist()[0],
            "document and implement the repository-default semantic operation families from API_SEMANTICS.md, including full local close helper, graceful send-half completion, read-side stop, send-side reset, whole-stream abort, structured error surfacing, open/cancel behavior, and accept visibility rules"
        );
        assert_eq!(
            Claim::StreamAdapterProfileV1.acceptance_checklist()[1],
            "provide one consistent convenience mapping or fuller documented control layer or both"
        );
        assert_eq!(
            reference_profile_claim_gate()[0],
            "repository-default stream-style CloseRead() emits STOP_SENDING(CANCELLED) when that convenience profile is exposed, while fuller control surfaces MAY additionally expose caller-selected codes and diagnostics for STOP_SENDING, RESET, and ABORT"
        );
        assert_eq!(
            reference_profile_claim_gate()[6],
            "repository-default liveness rules keep at most one outstanding protocol PING and do not treat weak local signals as strong progress"
        );
    }
}
