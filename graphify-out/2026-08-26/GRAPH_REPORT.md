# Graph Report - DSH  Security Assurance  (2026-08-26)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 2169 nodes · 4552 edges · 102 communities (89 shown, 13 thin omitted)
- Extraction: 91% EXTRACTED · 9% INFERRED · 0% AMBIGUOUS · INFERRED: 401 edges (avg confidence: 0.88)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `33b5613b`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- evaluation.ts
- contracts.ts
- export-delivery.ts
- workbench-remote.ts
- analyzer.ts
- evaluation-metrics.spec.ts
- finding-query.ts
- workbench-remote.spec.ts
- client/index.ts
- tools.ts
- src/index.ts
- SecurityAssuranceService
- WorkbenchOverlay.tsx
- control-plane-provider.ts
- SecurityAssuranceWorkbenchController
- files
- packed-browser-e2e.mjs
- packed-smoke.mjs
- Security Verdict
- Cross-Assessment Evidence reuse is contract-verified
- Evaluation Run Bundle
- One Security Service exposes explicit domain operations
- Security Service
- Analyzers receive only Attempt-scoped Capability Handles
- Role Attempt
- Evidence Eligibility Decision
- Security Service
- Public DTO
- Workbench is a Service Client not an authority
- deterministic-kernel.ts
- exports
- subject-freeze.ts
- calculateEffectivenessMetricsV1
- DigestEnvelopeV1
- workbench-client.spec.ts
- Fix Verification
- persistence.ts
- risk-decision.ts
- compilerOptions
- assessment-record.ts
- devDependencies
- .publishReady
- Security Service
- Obligations resolve as SATISFIED, NOT_APPLICABLE, or GAP
- canonicalJson
- host-repository-provider.ts
- SecurityPersistence
- builtin-node-package-lifecycle-analyzer.ts
- Bounded Harness Capabilities
- Release Conformance targets a packed fresh Harness installation
- AssessmentId
- assessment-list-query.ts
- Risk Decision
- package.json
- compilerOptions
- security-catalog.ts
- sealed-artifacts.ts
- WorkbenchPresentation
- Control Plane Adapter
- inject
- evaluateReleaseConstitutionV1
- peerDependencies
- scripts
- .submitAssessmentCommand
- SecurityAuthorityResolver
- .waitForAssessmentRevision
- Export Request
- generate-typert.mjs
- .constructor
- All Product Surfaces Share One Public Service Contract
- @deepseek-ai/dsh-agent
- @deepseek-ai/dsh-api-gateway
- @deepseek-ai/dsh-client-runtime
- @deepseek-ai/dsh-client-ui-primitives
- @deepseek-ai/dsh-client-ui-sidebar
- @deepseek-ai/dsh-client-ui-slots
- @deepseek-ai/dsh-home-paths
- @deepseek-ai/dsh-llm
- @deepseek-ai/dsh-tools
- @deepseek-ai/dsh-typert-protocol
- dependencies
- dsh-engineering-control-plane
- react
- peerDependenciesMeta
- tsdown.config.ts
- @deepseek-ai/dsh-subagent
- @deepseek-ai/dsh-typert-registry
- Finding Triage View Keeps Domain Dimensions Separate
- jsdom
- evidence-view.ts
- candidate-validation.ts
- vitest
- vitest.config.ts
- Hardening Portfolios Are Non-Mutating Design Evidence
- evidence-persistence.ts
- external-analyzer-validation.spec.ts
- host-repository-provider.spec.ts
- @deepseek-ai/dsh-client-ui-renderer
- @deepseek-ai/dsh-typert-generator

## God Nodes (most connected - your core abstractions)
1. `canonicalJson()` - 65 edges
2. `SecurityAssuranceWorkbenchController` - 64 edges
3. `SecurityAssuranceService` - 62 edges
4. `AssessmentId` - 59 edges
5. `SecurityInvocation` - 58 edges
6. `DigestEnvelopeV1` - 55 edges
7. `SecurityResult` - 48 edges
8. `SecurityPersistence` - 39 edges
9. `installWorkbenchUi()` - 38 edges
10. `files` - 37 edges

## Surprising Connections (you probably didn't know these)
- `call()` --indirect_call--> `preflight()`  [INFERRED]
  tests/workbench-client.spec.ts → src/internal/security-catalog.ts
- `Machine Providers Have Explicit Assessor Identity` --rationale_for--> `Assessment Engine`  [INFERRED]
  docs/adr/0015-machine-providers-have-explicit-assessor-identity.md → CONTEXT.md
- `Security Verdicts Do Not Own Mission Approval` --rationale_for--> `Assurance Submission`  [INFERRED]
  docs/adr/0002-security-verdicts-do-not-own-mission-approval.md → CONTEXT.md
- `Codex Security Is a Reference, Not a Required Runtime` --rationale_for--> `Security Assurance Plugin Boundary`  [INFERRED]
  docs/adr/0003-codex-security-is-a-reference-not-a-required-runtime.md → CONTEXT.md
- `Provider Capability Describes Support but Grants No Permission` --rationale_for--> `Security Policy`  [INFERRED]
  docs/adr/0016-provider-capability-describes-support-but-grants-no-permission.md → CONTEXT.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Assessment Integrity Closure** — docs_adr_0018_provider_composition_is_frozen_into_the_assessment_seal_assessment_seal, docs_adr_0019_coverage_is_proven_against_a_frozen_plan_coverage_plan, docs_adr_0027_only_sealed_assessments_produce_assurance_submissions_assurance_submission, docs_adr_0037_cross_assessment_evidence_reuse_is_contract_verified_cross_assessment_evidence_reuse [INFERRED 0.85]
- **Assessment Terminality Boundaries** — docs_adr_0122_only_coverage_reconciliation_can_seal_indeterminate_coverage_reconciliation, docs_adr_0123_cancellation_commits_only_after_proven_quiescence_cancellation_quiescence, docs_adr_0125_risk_acceptance_occurs_before_seal_in_a_decision_window_risk_decision_window, docs_adr_0128_seal_verdict_bundle_and_submission_commit_atomically_seal_publication, docs_adr_0133_assessment_aggregate_has_a_narrow_consistency_boundary_assessment_aggregate [INFERRED 0.85]
- **Attempt Authority and Fencing** — docs_adr_0144_execution_lease_takeover_requires_expiry_and_stronger_fencing_assessment_execution_lease, docs_adr_0153_analyzer_inputs_are_immutable_bounded_and_authority_free_analyzerinput, docs_adr_0156_attempt_cancellation_fences_late_results_and_requires_cleanup_cancellation_fence, docs_adr_0157_the_kernel_reserves_and_meters_nested_attempt_budgets_the_kernel_reserves_and_meters_nested_attempt_budgets, docs_adr_0158_scheduling_enforces_hierarchical_fair_concurrency_scheduling_enforces_hierarchical_fair_concurrency, docs_adr_0160_analyzers_receive_only_attempt_scoped_capability_handles_analyzers_receive_only_attempt_scoped_capability_handles [INFERRED 0.85]
- **Dormant Conformance and Health Boundary** — docs_adr_0245_contract_imports_are_side_effect_free_and_runtime_entries_start_dormant_decision, docs_adr_0253_the_invariant_entry_verifies_composition_without_patching_harness_invariant_entry, docs_adr_0254_the_conformance_module_tests_public_contracts_without_bypasses_conformance_module, docs_adr_0251_service_health_is_explicit_and_safe_mode_remains_queryable_runtime_health [INFERRED 0.85]
- **Durable Domain Command Lifecycle** — docs_adr_0091_one_security_service_exposes_explicit_domain_operations_security_service, docs_adr_0092_assessment_start_publishes_a_durable_receipt_assessment_receipt, docs_adr_0093_security_mutations_use_branded_identities_revisions_and_idempotency_security_mutation_contract, docs_adr_0094_interrupted_analyzer_attempts_require_explicit_resume_interrupted_analyzer_attempts_require_explicit_resume, docs_adr_0099_workbench_progress_is_revision_driven_long_polling_workbench_progress_is_revision_driven_long_polling [INFERRED 0.85]
- **Durable Execution Outcomes** — docs_adr_0020_assessment_executes_as_a_durable_phase_graph_assessment_workflow, docs_adr_0024_provider_unavailability_is_distinct_from_an_invalid_contribution_provider_unavailability_is_distinct_from_an_invalid_contribution, docs_adr_0025_analyzer_failure_requires_explicit_resume_explicit_resume, docs_adr_0026_cancellation_preserves_partial_evidence_but_produces_no_verdict_cancellation_preserves_partial_evidence_but_produces_no_verdict, docs_adr_0027_only_sealed_assessments_produce_assurance_submissions_only_sealed_assessments_produce_assurance_submissions [INFERRED 0.85]
- **Evaluation Evidence Chain** — docs_adr_0059_benchmarks_use_four_complementary_corpus_lanes_benchmark_corpus, docs_adr_0060_effectiveness_compares_fixed_baseline_and_product_arms_evaluation_arm, docs_adr_0067_evaluation_runs_are_immutable_and_pre_registered_evaluation_run_bundle, docs_adr_0069_ground_truth_adjudication_is_blinded_and_independent_adjudication_record, docs_adr_0070_finding_matching_is_predeclared_and_one_to_one_finding_matching_contract, docs_adr_0071_insufficient_benchmark_strata_are_inconclusive_benchmark_sufficiency [INFERRED 0.85]
- **Fail-Closed Verdict Semantics** — context_security_policy, context_policy_evaluator, context_assessment_coverage, context_security_verdict, docs_adr_0007_host_policy_and_a_deterministic_evaluator_own_verdict_semantics_decision, docs_adr_0008_security_verdicts_are_tristate_and_fail_closed_decision [INFERRED 0.85]
- **Plugin Integration Surface** — docs_adr_0088_security_assurance_ships_as_one_bundle_with_independent_entry_points_independent_entry_points, docs_adr_0090_installed_security_entry_points_are_dormant_by_default_installed_security_entry_points_are_dormant_by_default, docs_adr_0097_workbench_uses_package_owned_typert_remotes_package_owned_typert_remotes, docs_adr_0098_workbench_is_an_additive_harness_web_surface_workbench_is_an_additive_harness_web_surface, docs_adr_0100_security_assurance_plugin_boundary_public_harness_capability_seams [INFERRED 0.85]
- **Policy and Validation Governance** — docs_adr_0022_policy_layers_may_strengthen_but_not_weaken_the_baseline_monotonic_policy_composition, docs_adr_0028_severity_confidence_and_policy_significance_are_independent_security_finding_dimensions, docs_adr_0029_risk_acceptance_is_authorized_scoped_and_non_destructive_risk_acceptance, docs_adr_0035_findings_require_explicit_validation_state_evidence_contract [INFERRED 0.85]
- **Protected Evidence Lifecycle** — docs_adr_0044_canonical_assessment_bundles_are_machine_authoritative_canonical_assessment_bundle, docs_adr_0053_sensitive_evidence_is_protected_and_secrets_are_never_retained_security_evidence_store, docs_adr_0054_exports_use_audience_specific_redaction_profiles_decision, docs_adr_0056_retention_purges_payloads_with_auditable_tombstones_decision [INFERRED 0.85]
- **Qualified Analyzer Execution** — docs_adr_0108_analyzer_execution_class_determines_verdict_eligibility_analyzer_execution_class, docs_adr_0109_v0_1_gate_bearing_local_analyzers_use_bounded_harness_capabilities_bounded_harness_capabilities, docs_adr_0110_model_egress_uses_minimal_redacted_source_slices_source_slice, docs_adr_0111_ts_js_node_support_uses_a_hybrid_analyzer_portfolio_hybrid_analyzer_portfolio, docs_adr_0113_standard_and_deep_have_explicit_qualified_analysis_paths_qualified_analysis_path, docs_adr_0114_required_analyzer_failure_cannot_become_security_failure_or_satisfaction_coverage_reconciliation [INFERRED 0.85]
- **Qualified Release Evidence Closure** — docs_adr_0080_releases_must_be_non_inferior_in_every_mandatory_stratum_non_inferiority_margins, docs_adr_0081_the_first_public_candidate_is_0_1_0_rc_1_release_gates, docs_adr_0082_public_security_claims_are_evidence_and_scope_bound_support_claim, docs_adr_0083_the_security_product_has_a_stricter_self_security_release_gate_self_security_release_gate, docs_adr_0084_stable_support_requires_windows_linux_and_macos_proof_conformance_evidence, docs_adr_0086_public_scorecards_prove_method_without_exposing_holdouts_security_scorecard, docs_adr_0087_stable_promotion_uses_the_exact_qualified_build_exact_qualified_build [INFERRED 0.85]
- **Release Qualification Closure** — docs_adr_0065_capability_conformance_is_a_reusable_provider_contract_kit_capability_conformance_test_kit, docs_adr_0061_effectiveness_prioritizes_validated_risk_and_honest_indeterminacy_security_effectiveness, docs_adr_0062_utility_measures_risk_reduction_against_human_and_runtime_cost_product_utility, docs_adr_0068_development_qualification_and_release_corpora_are_separated_release_holdout, docs_adr_0078_release_thresholds_combine_hard_floors_and_pre_holdout_calibration_release_constitution [INFERRED 0.85]
- **Requalification and Holdout Rotation** — docs_adr_0073_model_and_provider_drift_requires_requalification_decision, docs_adr_0075_benchmark_major_changes_require_bridge_runs_bridge_run, docs_adr_0079_exposed_release_holdouts_are_retired_after_a_failed_candidate_decision, docs_adr_0060_effectiveness_compares_fixed_baseline_and_product_arms_evaluation_arm, docs_adr_0068_development_qualification_and_release_corpora_are_separated_release_holdout [INFERRED 0.85]
- **Sealed Assurance Exchange** — context_security_evidence_store, context_assessment_seal, context_assurance_submission, docs_adr_0010_assurance_integration_exchanges_sealed_submissions_decision [INFERRED 0.85]
- **Single Package Contract Surface** — docs_adr_0244_one_package_exposes_separated_runtime_and_contract_entry_points_dsh_security_assurance_package, docs_adr_0235_security_service_is_the_sole_external_business_interface_security_service, docs_adr_0239_assessment_engine_is_package_private_and_hides_phase_orchestration_assessment_engine, docs_adr_0225_all_public_surfaces_pass_one_semantic_parity_suite_surface_parity_suite [INFERRED 0.85]
- **Trusted Security Service Boundary** — docs_adr_0101_security_service_is_sole_mutation_boundary_security_service, docs_adr_0106_assessment_execution_uses_revision_cas_leases_and_fencing_assessment_execution_lease, docs_adr_0107_sensitive_evidence_requires_an_explicit_key_provider_evidence_key_provider, docs_adr_0118_security_authority_is_derived_from_the_real_caller_channel_security_authority_resolver, docs_adr_0121_security_service_exposes_fixed_commands_and_bounded_queries_decision [INFERRED 0.85]
- **Analyzer Admission and Eligibility** — docs_adr_0148_analyzer_identity_binds_version_schema_and_build_analyzer_identity, docs_adr_0149_analyzer_descriptors_are_frozen_validated_pure_data_analyzer_descriptor, docs_adr_0150_analyzer_capabilities_use_a_versioned_taxonomy_capability_vocabulary, docs_adr_0151_the_kernel_computes_and_freezes_verdict_eligibility_eligibility_decision, docs_adr_0163_gate_bearing_analyzers_require_scoped_qualification_records_analyzer_qualification_record [INFERRED 0.95]
- **Candidate to Sealed Finding Lineage** — docs_adr_0176_role_contributions_are_versioned_structured_proposals_role_contribution, docs_adr_0181_candidates_remain_immutable_and_validation_creates_separate_outcomes_candidate_finding, docs_adr_0182_candidate_admission_enforces_schema_provenance_anchors_and_bounds_decision, docs_adr_0183_candidate_clusters_never_merge_evidence_automatically_decision, docs_adr_0181_candidates_remain_immutable_and_validation_creates_separate_outcomes_validation_outcome, docs_adr_0184_finding_changes_append_revisions_and_sealed_versions_remain_immutable_finding_revision [INFERRED 0.95]
- **Control Plane Assessment Lifecycle** — docs_adr_0295_control_plane_integration_is_an_optional_by_value_adapter_control_plane_adapter, docs_adr_0295_control_plane_integration_is_an_optional_by_value_adapter_security_submission, docs_adr_0296_control_plane_cancellation_resolves_only_an_existing_assessment_decision, docs_adr_0297_cancellation_crash_checkpoint_preserves_the_exact_assessment_decision, docs_adr_0298_control_plane_external_failure_uses_provider_neutral_constructor_external_assessment_failure_v1, docs_adr_0299_control_plane_assurance_retry_starts_a_distinct_assessment_decision, docs_adr_0300_control_plane_repository_binding_precedes_assessment_start_repository_binding_assertion, docs_adr_0301_host_repository_provider_is_a_trusted_composition_adapter_decision [INFERRED 0.95]
- **Coverage Planning Closure** — docs_adr_0202_coverage_planning_requires_an_evidence_backed_subject_inventory_subject_inventory, docs_adr_0203_coverage_obligations_are_stable_typed_completion_contracts_coverage_obligation, docs_adr_0204_the_coverage_plan_is_an_immutable_obligation_dependency_graph_coverage_plan, docs_adr_0201_policy_compilation_is_deterministic_and_recorded_policy_compilation_record [INFERRED 0.95]
- **Coverage Resolution Closure** — docs_adr_0205_plan_amendments_only_add_or_strengthen_obligations_plan_amendment, docs_adr_0206_coverage_claims_are_proposals_and_the_kernel_resolves_them_coverage_resolution, docs_adr_0207_obligations_resolve_as_satisfied_not_applicable_or_gap_coverage_obligation, docs_adr_0208_not_applicable_requires_eligible_negative_proof_not_applicable_proof, docs_adr_0209_coverage_hierarchy_requires_every_mandatory_child_coverage_hierarchy_requires_every_mandatory_child, docs_adr_0210_advisory_work_cannot_compensate_for_mandatory_gaps_advisory_work_cannot_compensate_for_mandatory_gaps [INFERRED 0.95]
- **Deterministic Policy Compilation** — docs_adr_0198_security_policies_are_versioned_declarative_data_security_policy, docs_adr_0199_policy_layers_preserve_source_identity_and_trust_policy_layer, docs_adr_0200_policy_composition_is_monotonic_and_conflicts_fail_closed_policy_lattice, docs_adr_0201_policy_compilation_is_deterministic_and_recorded_policy_compilation_record [INFERRED 0.95]
- **Governed Export Delivery Lifecycle** — docs_adr_0291_export_ui_previews_profile_and_destination_while_service_performs_delivery_export_request, docs_adr_0303_export_delivery_recovery_is_service_owned_and_bounded_export_delivery_worker, docs_adr_0303_export_delivery_recovery_is_service_owned_and_bounded_decision, docs_adr_0304_export_expiry_uses_two_phase_exact_target_reaping_export_tombstone, docs_adr_0304_export_expiry_uses_two_phase_exact_target_reaping_decision [INFERRED 0.95]
- **Governed Role Execution** — docs_adr_0164_assessment_roles_come_from_a_fixed_security_role_catalog_security_role_catalog, docs_adr_0165_role_definitions_are_versioned_immutable_product_assets_role_definition, docs_adr_0166_the_kernel_admits_roles_from_policy_and_the_coverage_plan_role_admission, docs_adr_0167_prompt_compilation_separates_trusted_rules_from_untrusted_data_prompt_compiler, docs_adr_0168_role_agents_receive_minimal_context_grants_context_grant, docs_adr_0169_each_role_attempt_uses_a_fresh_isolated_subagent_session_role_attempt, docs_adr_0170_role_tools_are_fixed_least_privilege_manifests_role_tool_manifest [INFERRED 0.95]
- **Immutable Evidence and Seal Closure** — docs_adr_0140_evidence_enters_through_staged_verified_publication_evidence_publication, docs_adr_0141_digests_use_versioned_deterministic_envelopes_digest_envelope, docs_adr_0128_seal_verdict_bundle_and_submission_commit_atomically_seal_publication, docs_adr_0127_official_exports_require_a_sealed_assessment_decision [INFERRED 0.95]
- **Immutable Role Collaboration and Convergence** — docs_adr_0176_role_contributions_are_versioned_structured_proposals_role_contribution, docs_adr_0172_roles_communicate_through_immutable_governed_artifacts_decision, docs_adr_0173_deep_independent_passes_remain_blind_until_initial_submission_decision, docs_adr_0174_cross_challenge_never_rewrites_an_original_contribution_decision, docs_adr_0175_evidence_contracts_not_agent_votes_determine_convergence_evidence_convergence [INFERRED 0.95]
- **Immutable Subject Admission** — docs_adr_0119_assessment_subjects_come_from_a_host_owned_repository_registry_repository_registry, docs_adr_0120_start_requests_reference_host_resolved_security_configuration_decision, docs_adr_0102_assessment_subject_sources_are_explicit_and_immutable_assessment_subject, docs_adr_0103_analyzers_read_only_content_addressed_subject_snapshots_subject_snapshot [INFERRED 0.95]
- **Independent Product Proof** — docs_adr_0057_product_proof_separates_conformance_from_effectiveness_decision, docs_adr_0058_ground_truth_is_hidden_and_independently_adjudicated_ground_truth_manifest, docs_adr_0058_ground_truth_is_hidden_and_independently_adjudicated_decision [INFERRED 0.95]
- **Inward Deep Module Architecture** — docs_adr_0235_security_service_is_the_sole_external_business_interface_security_service, docs_adr_0237_callers_act_through_resolver_issued_security_invocations_security_invocation, docs_adr_0238_security_assessment_kernel_is_a_pure_deep_module_security_assessment_kernel, docs_adr_0239_assessment_engine_is_package_private_and_hides_phase_orchestration_assessment_engine, docs_adr_0240_sqlite_persistence_is_a_package_private_deep_module_sqlite_persistence, docs_adr_0241_evidence_persistence_is_a_separate_package_private_deep_module_evidence_persistence, docs_adr_0243_dependencies_point_inward_toward_domain_values_and_the_kernel_decision [INFERRED 0.95]
- **Non-authoritative Workbench Projection** — docs_adr_0275_workbench_is_a_service_client_not_an_authority_security_workbench, docs_adr_0276_workbench_mounts_as_an_additive_launcher_and_overlay_workbench_mounts_as_an_additive_launcher_and_overlay, docs_adr_0277_workbench_information_architecture_is_fixed_for_v0_1_workbench_information_architecture_is_fixed_for_v0_1, docs_adr_0278_workbench_route_state_contains_only_low_sensitivity_identifiers_workbench_route_state_contains_only_low_sensitivity_identifiers, docs_adr_0281_assessment_progress_is_a_revision_bound_phase_and_coverage_view_phase_graph_view, docs_adr_0282_role_cards_show_governed_lineage_not_chat_authority_role_cards_show_governed_lineage_not_chat_authority, docs_adr_0283_role_detail_is_immutable_and_cannot_accept_ad_hoc_instructions_role_detail_is_immutable_and_cannot_accept_ad_hoc_instructions, docs_adr_0284_deep_independent_passes_remain_hidden_from_peers_until_frozen_evidence_convergence [INFERRED 0.95]
- **Packed Release Conformance Suite** — docs_adr_0216_release_conformance_targets_a_packed_fresh_harness_installation_release_conformance, docs_adr_0217_the_reference_test_host_uses_real_harness_composition_reference_test_host, docs_adr_0219_deterministic_reference_fakes_exercise_official_seams_reference_fakes, docs_adr_0220_the_transition_matrix_receives_model_based_conformance_transition_matrix, docs_adr_0221_crash_conformance_hard_kills_at_named_persistence_checkpoints_crash_checkpoints, docs_adr_0222_multiprocess_races_prove_cas_leases_fencing_and_sealing_multi_process_race_suite, docs_adr_0223_adversarial_filesystem_proof_is_platform_specific_adversarial_filesystem_proof_is_platform_specific, docs_adr_0224_canonical_security_artifacts_have_reviewed_golden_vectors_canonical_golden_vectors [INFERRED 0.95]
- **Policy Verdict and Seal Closure** — docs_adr_0211_policy_significance_is_derived_by_a_deterministic_rule_trace_evaluation_trace, docs_adr_0212_policy_evaluation_uses_one_recorded_instant_evaluation_instant, docs_adr_0213_a_proven_blocking_violation_takes_precedence_over_incomplete_coverage_a_proven_blocking_violation_takes_precedence_over_incomplete_coverage, docs_adr_0214_the_policy_evaluator_is_pure_and_emits_a_complete_trace_policy_evaluator, docs_adr_0215_sealing_requires_an_independent_deterministic_readiness_check_kernel_seal_readiness_check [INFERRED 0.95]
- **Public Service Contract Surface** — docs_adr_0246_public_dtos_are_versioned_json_safe_and_runtime_validated_public_dto, docs_adr_0247_public_operations_return_one_typed_security_result_envelope_security_result, docs_adr_0248_commands_return_receipts_and_queries_return_immutable_snapshots_command_receipt, docs_adr_0255_v0_1_service_operations_are_fixed_and_explicit_service_operation_catalog, docs_adr_0257_invocation_request_and_local_execution_options_are_separate_security_invocation, docs_adr_0252_transport_adapters_contain_no_domain_policy_transport_adapter [INFERRED 0.95]
- **Release Proof Closure** — docs_adr_0225_all_public_surfaces_pass_one_semantic_parity_suite_surface_parity_suite, docs_adr_0226_workbench_e2e_uses_a_packed_host_real_browser_and_real_authority_workbench_e2e, docs_adr_0227_lifecycle_conformance_proves_dormancy_activation_disposal_and_hmr_lifecycle_conformance, docs_adr_0230_the_versioned_metrics_engine_has_synthetic_golden_oracles_metrics_engine, docs_adr_0231_conformance_mutants_must_be_killed_before_release_conformance_mutant_suite, docs_adr_0232_resource_proof_measures_limits_leaks_and_recovery_resource_proof, docs_adr_0233_release_evidence_manifests_bind_exact_artifacts_to_proof_release_evidence_manifest, docs_adr_0234_deterministic_failures_cannot_be_erased_by_reruns_decision [INFERRED 0.95]
- **Remediation Evidence Closure** — docs_adr_0042_remediation_cases_own_one_primary_finding_remediation_case, docs_adr_0050_patch_generation_and_application_use_separate_authority_patch_artifact, docs_adr_0051_finding_resolution_requires_a_new_sealed_assessment_fix_verification, docs_adr_0051_finding_resolution_requires_a_new_sealed_assessment_decision [INFERRED 0.95]
- **Repository to Assessment Creation Closure** — docs_adr_0249_repository_administration_is_explicit_versioned_and_non_destructive_repository_administration, docs_adr_0261_repository_mutations_use_revision_cas_and_idempotency_mutation_envelope, docs_adr_0263_target_selectors_use_mode_specific_discriminated_schemas_target_selector, docs_adr_0264_assessment_creation_commits_only_after_subject_freeze_succeeds_subject_freeze, docs_adr_0248_commands_return_receipts_and_queries_return_immutable_snapshots_command_receipt [INFERRED 0.95]
- **Revision and Disclosure Contract** — docs_adr_0265_assessment_queries_return_revision_bound_snapshots_and_watermarked_lists_assessment_snapshot, docs_adr_0266_revision_wait_returns_a_change_signal_not_an_event_stream_revision_wait_result, docs_adr_0268_finding_queries_separate_redacted_summaries_from_revision_detail_finding_detail_view, docs_adr_0269_evidence_disclosure_is_purpose_and_profile_bound_evidence_view_profile, docs_adr_0271_bundle_manifest_is_a_view_and_submission_is_self_contained_assurance_submission [INFERRED 0.95]
- **Semantic Result Authority Boundary** — docs_adr_0151_the_kernel_computes_and_freezes_verdict_eligibility_the_kernel_computes_and_freezes_verdict_eligibility, docs_adr_0154_analyzer_contributions_are_versioned_and_cannot_decide_verdicts_analyzercontribution, docs_adr_0155_runner_progress_events_are_bounded_and_non_authoritative_runner_progress_events_are_bounded_and_non_authoritative, docs_adr_0162_authoritative_contributions_are_not_reused_across_assessments_in_v0_1_authoritative_contributions_are_not_reused_across_assessments_in_v0_1 [INFERRED 0.95]
- **Service-Projected Workbench Authority** — docs_adr_0285_available_actions_are_service_projected_not_client_inferred_available_actions, docs_adr_0285_available_actions_are_service_projected_not_client_inferred_assessment_snapshot, docs_adr_0286_blocked_view_explains_recovery_without_offering_a_bypass_blocked_recovery_view, docs_adr_0287_finding_triage_view_keeps_domain_dimensions_separate_finding_triage_view, docs_adr_0288_evidence_view_starts_redacted_and_reauthorizes_sensitive_content_evidence_view, docs_adr_0289_risk_decision_form_records_a_governed_immutable_decision_risk_decision, docs_adr_0290_critical_break_glass_requires_two_independent_operator_invocations_dual_authority_attestation, docs_adr_0292_reconnect_recovers_from_id_revision_and_idempotency_security_invocation [INFERRED 0.95]
- **Shared Assessment Engine Entry Points** — context_assessment_engine, context_security_service, docs_adr_0005_one_assessment_engine_serves_both_entry_points_decision, docs_adr_0012_standalone_use_exposes_assessment_control_not_a_second_mission_system_decision [INFERRED 0.95]
- **Transactional Assessment Persistence** — docs_adr_0133_assessment_aggregate_has_a_narrow_consistency_boundary_assessment_aggregate, docs_adr_0134_persistence_combines_a_revision_journal_with_current_projections_revision_journal, docs_adr_0134_persistence_combines_a_revision_journal_with_current_projections_current_projection, docs_adr_0135_commands_publish_durable_work_transactionally_durable_work_item, docs_adr_0137_idempotency_binds_authority_operation_target_and_request_idempotency_record, docs_adr_0138_state_transitions_are_exhaustive_and_declarative_transition_matrix, docs_adr_0139_execution_may_repeat_but_result_admission_is_at_most_once_result_admission [INFERRED 0.95]
- **Validation Evidence Chain** — docs_adr_0185_weakness_classification_is_versioned_namespaced_and_explicit_about_unknowns_weakness_classification, docs_adr_0186_source_anchors_bind_subject_content_and_stable_spans_source_anchor, docs_adr_0187_evidence_kinds_use_a_versioned_core_registry_evidence_type_registry, docs_adr_0188_the_kernel_decides_evidence_eligibility_per_claim_and_contract_evidence_eligibility_decision, docs_adr_0189_the_kernel_freezes_validation_contract_resolution_validation_contract_resolution, docs_adr_0190_validation_outcomes_are_validated_rejected_or_unresolved_validation_outcome, docs_adr_0197_evidence_links_bind_each_use_to_claim_contract_and_eligibility_evidence_link [INFERRED 0.95]
- **Versioned Mutation Authority** — docs_adr_0267_resume_and_cancel_require_revision_idempotency_and_reason_resume_and_cancel_require_revision_idempotency_and_reason, docs_adr_0270_risk_decisions_derive_authority_and_critical_acceptance_requires_two_risk_decision, docs_adr_0273_mutations_share_a_versioned_idempotent_cas_envelope_mutation_envelope, docs_adr_0274_contract_majors_govern_semantic_compatibility_contract_version, docs_adr_0279_new_assessment_wizard_uses_registered_choices_and_resolved_values_start_assessment_request, docs_adr_0280_start_preflight_discloses_the_effective_contract_before_confirmation_start_preflight [INFERRED 0.95]

## Communities (102 total, 13 thin omitted)

### Community 0 - "evaluation.ts"
Cohesion: 0.01
Nodes (147): AirGapAccessAuditV1, airGapAccessAuditV1Schema, airGappedEvaluationAssemblyRequestV1Schema, AirGappedEvaluationAssemblyV1, AirGappedFindingAdjudicationV1, airGappedFindingAdjudicationV1Schema, airGappedInvalidationReasonV1Schema, AirGappedRunnerInputV1 (+139 more)

### Community 1 - "contracts.ts"
Cohesion: 0.02
Nodes (90): assessmentAvailableActionV1Schema, AssessmentBlockedRecoveryV1, assessmentBlockedRecoveryV1Schema, assessmentCancellationResultSchema, AssessmentCoverageResolutionV1, assessmentCoverageResolutionV1Schema, assessmentListItemV1Schema, assessmentListResultSchema (+82 more)

### Community 2 - "export-delivery.ts"
Cohesion: 0.05
Nodes (49): EXPORT_DELIVERY_MAX_ATTEMPTS, EXPORT_DOWNLOAD_CAPABILITY_LIFETIME_SECONDS, ExportDeliveryAttemptFailureCodeV1, ExportDestinationViewV1, exportDestinationViewV1Schema, ExportDownloadV1, exportDownloadV1Schema, ExportId (+41 more)

### Community 3 - "workbench-remote.ts"
Cohesion: 0.07
Nodes (35): AssessmentCancellationReceiptV1, AssessmentListPageV1, AssessmentResumeReceiptV1, AssessmentSnapshotV1, CancelAssessmentRequest, ExportRequestReceiptV1, ExportViewV1, FindingListPageV1 (+27 more)

### Community 4 - "analyzer.ts"
Cohesion: 0.07
Nodes (44): analyzerCandidateFindingV1Schema, analyzerContributionV1Schema, AnalyzerDescriptorV1, analyzerDescriptorV1Schema, AnalyzerEligibilityDecisionV1, analyzerEligibilityDecisionV1Schema, AnalyzerEligibilityReasonV1, analyzerEvidenceDraftV1Schema (+36 more)

### Community 5 - "evaluation-metrics.spec.ts"
Cohesion: 0.05
Nodes (46): AIR_GAPPED_EVALUATION_ENGINE_ID, AirGappedEvaluationAssemblyRequestV1, airGappedEvaluationAssemblyV1Schema, AirGappedEvaluationInputError, airGappedRunnerInputV1Schema, airGappedRunnerResultV1Schema, EFFECTIVENESS_METRICS_ENGINE_ID, effectivenessMetricsRequestV1Schema (+38 more)

### Community 6 - "finding-query.ts"
Cohesion: 0.06
Nodes (45): evidenceConfidenceSchema, FindingDetailDimensionV1, findingDetailViewV1Schema, findingListPageV1Schema, policySignificanceSchema, SecuritySubmissionArtifactV1, technicalSeveritySchema, assessmentIdSchema (+37 more)

### Community 7 - "workbench-remote.spec.ts"
Cohesion: 0.07
Nodes (35): RISK_DECISION_WINDOW_CONTROL_ID, runtimeHealthSnapshotSchema, RESOLVE_TRUSTED_INVOCATION, resolveTrustedInvocation(), SecurityCallerChannelKind, SecurityPermission, TrustedCallerChannel, TrustedInvocationIssuer (+27 more)

### Community 8 - "client/index.ts"
Cohesion: 0.06
Nodes (40): ASSESSMENT_COMMAND_IDLE, browserSha256Hex(), CLOSED_STATE, Context, decodeExportBase64(), @deepseek-ai/cordis, @deepseek-ai/dsh-client-ui-slots, EVIDENCE_NOT_LOADED (+32 more)

### Community 9 - "tools.ts"
Cohesion: 0.05
Nodes (27): AssessmentState, cancelAssessmentRequestSchema, getAssessmentRequestSchema, listFindingsRequestSchema, requestExportRequestSchema, resumeAssessmentRequestSchema, SecurityVerdict, startAssessmentRequestSchema (+19 more)

### Community 10 - "src/index.ts"
Cohesion: 0.06
Nodes (32): DisableRepositoryRequest, disableRepositoryRequestSchema, EVIDENCE_VIEW_BOUNDED_JSON_LIFETIME_MS, GetAssuranceSubmissionRequest, getAssuranceSubmissionRequestSchema, getBundleManifestRequestSchema, getCatalogRequestSchema, getEvidenceViewRequestSchema (+24 more)

### Community 11 - "SecurityAssuranceService"
Cohesion: 0.26
Nodes (11): InvocationOptions, SecurityInvocation, SecurityResult, assessmentSelectionIsConsistent(), failure(), interruption(), requestedStrongerControlsAreValid(), SecurityAssuranceService (+3 more)

### Community 12 - "WorkbenchOverlay.tsx"
Cohesion: 0.06
Nodes (24): SecurityAssuranceWorkbenchStateV1, WorkbenchAssessmentCommandReasonV1, WorkbenchAssessmentCommandStateV1, WorkbenchEvidenceStateV1, WorkbenchExportStateV1, WorkbenchFindingsStateV1, WorkbenchRiskDecisionSubmissionStateV1, WorkbenchRiskDecisionSubmissionV1 (+16 more)

### Community 13 - "control-plane-provider.ts"
Cohesion: 0.06
Nodes (36): repositoryIdSchema, SECURITY_ASSURANCE_PRODUCT_VERSION, assessmentCancellationIdempotencyKey(), assessmentIdempotencyKey(), assessmentResumeIdempotencyKey(), canonicalSubmissionEvidence(), claimedOutcome(), configuredRepositoryId() (+28 more)

### Community 14 - "SecurityAssuranceWorkbenchController"
Cohesion: 0.21
Nodes (4): installWorkbenchUi(), SecurityAssuranceWorkbenchController, AssessmentSelection(), WorkbenchOverlay()

### Community 15 - "files"
Cohesion: 0.05
Nodes (37): files, cordis.patch.yml, lib/analyzer.js, lib/client.js, lib/client.js.map, lib/contracts.js, lib/control-plane-provider.js, lib/evaluation.js (+29 more)

### Community 16 - "packed-browser-e2e.mjs"
Cohesion: 0.09
Nodes (31): artifactRoot, assertAccessibleControls(), assertFocused(), assertNoForbiddenBrowserState(), callWorkbenchBridge(), configureReferenceHost(), createFixtureRepository(), dismissReferenceHostOnboarding() (+23 more)

### Community 17 - "packed-smoke.mjs"
Cohesion: 0.06
Nodes (12): artifactRoot, consumerRoot, controlPlaneRoot, createFixtureRepository(), execute, executeNpm(), failedRepositoryRoot, indeterminateRepositoryRoot (+4 more)

### Community 18 - "Security Verdict"
Cohesion: 0.09
Nodes (35): Assessment Coverage, Assessment Engine, Assessment Seal, Assessment State, Assessment Subject, Assurance Submission, DSH Security Assurance, Policy Evaluator (+27 more)

### Community 19 - "Cross-Assessment Evidence reuse is contract-verified"
Cohesion: 0.09
Nodes (35): Assurance Execution Context, Gate-bearing assessment requires bounded execution, Assessment Seal, Provider Composition is frozen into the Assessment Seal, Coverage is proven against a frozen Plan, Coverage Plan, Assessment executes as a durable phase graph, Assessment Workflow (+27 more)

### Community 20 - "Evaluation Run Bundle"
Cohesion: 0.09
Nodes (35): Benchmark Corpus, Benchmarks Use Four Complementary Corpus Lanes, Effectiveness Compares Fixed Baseline and Product Arms, Evaluation Arm, Matched-Budget Comparison, Effectiveness Prioritizes Validated Risk and Honest Indeterminacy, Security Effectiveness, Utility Measures Risk Reduction Against Human and Runtime Cost (+27 more)

### Community 21 - "One Security Service exposes explicit domain operations"
Cohesion: 0.09
Nodes (35): Non-inferiority Margins, Releases must be non-inferior in every mandatory stratum, Release Gates, The first public Candidate is 0.1.0-rc.1, Public security claims are Evidence- and scope-bound, Support Claim, Self-Security Release Gate, The security product has a stricter self-security Release Gate (+27 more)

### Community 22 - "Security Service"
Cohesion: 0.07
Nodes (35): Coverage Reconciliation, Only Coverage Reconciliation Can Seal INDETERMINATE, Cancellation Quiescence, Cancellation Commits Only After Proven Quiescence, Resume Preserves the Frozen Assessment Contract, Risk Acceptance Occurs Before Seal in a Decision Window, Risk Decision Window, Risk Acceptance Requires Human or Control Plane Decision Authority (+27 more)

### Community 23 - "Analyzers receive only Attempt-scoped Capability Handles"
Cohesion: 0.09
Nodes (35): Crash recovery never silently resumes Assessment work, Startup Recovery Reconciliation, Assessment Execution Lease, Execution Lease takeover requires expiry and stronger fencing, Opaque Keyset Cursor, Pagination cursors bind query authority and watermark, Wait for revision is bounded cancellable and transaction-free, waitForRevision (+27 more)

### Community 24 - "Role Attempt"
Cohesion: 0.07
Nodes (35): Assessment Roles Come from a Fixed Security Role Catalog, Security Role Catalog, Role Definitions Are Versioned Immutable Product Assets, Role Definition, The Kernel Admits Roles from Policy and the Coverage Plan, Role Admission, Prompt Compilation Separates Trusted Rules from Untrusted Data, Prompt Compiler (+27 more)

### Community 25 - "Evidence Eligibility Decision"
Cohesion: 0.07
Nodes (35): Weakness Classification Is Versioned, Namespaced, and Explicit About Unknowns, Weakness Classification, Source Anchors Bind Subject Content and Stable Spans, Source Anchor, Evidence Kinds Use a Versioned Core Registry, Evidence Type Registry, The Kernel Decides Evidence Eligibility per Claim and Contract, Evidence Eligibility Decision (+27 more)

### Community 26 - "Security Service"
Cohesion: 0.08
Nodes (35): All Public Surfaces Pass One Semantic Parity Suite, Surface Parity Suite, Workbench E2E Uses a Packed Host, Real Browser, and Real Authority, Workbench E2E, Lifecycle Conformance Proves Dormancy, Activation, Disposal, and HMR, Lifecycle Conformance, Benchmark Arms and Repetitions Are State-Isolated, Evaluation Arm (+27 more)

### Community 27 - "Public DTO"
Cohesion: 0.07
Nodes (35): Contract Imports Are Side-Effect-Free and Runtime Entries Start Dormant, Public DTOs Are Versioned, JSON-Safe, and Runtime-Validated, Public DTO, Public Operations Return One Typed Security Result Envelope, Security Result, Command Receipt, Commands Return Receipts and Queries Return Immutable Snapshots, Repository Administration Is Explicit, Versioned, and Non-Destructive (+27 more)

### Community 28 - "Workbench is a Service Client not an authority"
Cohesion: 0.09
Nodes (35): Assessment queries return revision-bound Snapshots and watermarked lists, Assessment Snapshot, Revision Wait Result, Revision wait returns a change signal not an event stream, Cancellation Request Receipt, Resume and Cancel require revision, idempotency, and reason, Finding Detail View, Finding queries separate redacted summaries from revision detail (+27 more)

### Community 29 - "deterministic-kernel.ts"
Cohesion: 0.22
Nodes (19): AssessmentCoverageSnapshotV1, AssessmentProfileId, AssessmentTargetSelectorV1, contributionAsJson(), NodePackageLifecycleAnalyzerContributionV1, AdmittedAnalyzerInputV1, analyzerEvidenceIsEligible(), analyzerProviderComposition() (+11 more)

### Community 30 - "exports"
Cohesion: 0.06
Nodes (33): default, types, default, types, default, types, default, types (+25 more)

### Community 31 - "subject-freeze.ts"
Cohesion: 0.17
Nodes (27): binaryDigest(), assertSubjectBounds(), canceled(), decodeUtf8(), exactCommit(), freezeSubject(), GitTreeEntry, lockTree() (+19 more)

### Community 32 - "calculateEffectivenessMetricsV1"
Cohesion: 0.09
Nodes (33): airGapCaseKey(), assembleAirGappedEvaluationV1(), calculateDistribution(), calculateEffectivenessMetricsV1(), calculateNonInferiorityComparison(), calculatePairedArmComparisonV1(), calculatePairedUtilityComparison(), calculateRepetitionAnalysis() (+25 more)

### Community 33 - "DigestEnvelopeV1"
Cohesion: 0.14
Nodes (19): AnalyzerCandidateFindingV1, AssessmentSealV1, AssessmentSubjectReceiptV1, AssessmentSubjectSourceV1, BundleManifestV1, BundleRecordDescriptorV1, ExportArtifactTombstoneV1, FindingEvidenceLinkMetadataV1 (+11 more)

### Community 34 - "workbench-client.spec.ts"
Cohesion: 0.10
Nodes (20): apply(), inject, FindingSummaryV1, SecurityAssessmentFindingSummaryV1, WorkbenchEvidenceDisclosureViewV1, assessmentListItem(), authorityContextId(), call() (+12 more)

### Community 35 - "Fix Verification"
Cohesion: 0.08
Nodes (29): Finding Identity Is Local and Lineage Is Explicit, Finding Fingerprint, Validation Is Governed by Weakness-Specific Contracts, Validation Contract, Attack Path, Attack Paths Are Evidence Graphs, Not Dismissal Prerequisites, Remediation Cases Own One Primary Finding, Remediation Case (+21 more)

### Community 36 - "persistence.ts"
Cohesion: 0.09
Nodes (27): assessmentCancellationReceiptV1Schema, AssessmentOperatorReasonV1, assessmentReceiptV1Schema, assessmentResumeReceiptV1Schema, RepositoryBindingsV1, repositoryCommandReceiptV1Schema, repositorySnapshotV1Schema, RiskDecisionAuthorizationModeV1 (+19 more)

### Community 37 - "risk-decision.ts"
Cohesion: 0.17
Nodes (14): AnalyzerEvidenceDraftV1, AssessmentAvailableActionV1, AvailableRiskDecisionOptionV1, SecuritySubmissionJsonV1, TechnicalSeverity, ResolvedSecurityAuthority, CandidateValidationResultV1, DeterministicAssessmentOutcomeV1 (+6 more)

### Community 38 - "compilerOptions"
Cohesion: 0.07
Nodes (26): node, compilerOptions, allowImportingTsExtensions, declaration, declarationMap, esModuleInterop, exactOptionalPropertyTypes, jsx (+18 more)

### Community 39 - "assessment-record.ts"
Cohesion: 0.13
Nodes (15): assessmentCoverageSnapshotV1Schema, assessmentModeSchema, assessmentOperatorReasonV1Schema, assessmentProfileIdSchema, assessmentSealV1Schema, assessmentStateSchema, assessmentSubjectSourceV1Schema, assessmentTargetSelectorV1Schema (+7 more)

### Community 40 - "devDependencies"
Cohesion: 0.09
Nodes (23): @deepseek-ai/dsh-client-test-runtime, @deepseek-ai/dsh-session, @deepseek-ai/dsh-subprocess-local, @deepseek-ai/dsh-system-prompt, devDependencies, @deepseek-ai/dsh-client-test-runtime, @deepseek-ai/dsh-session, @deepseek-ai/dsh-subprocess-local (+15 more)

### Community 41 - ".publishReady"
Cohesion: 0.17
Nodes (5): matchesBundleManifest(), matchesEvidenceDisclosure(), matchesEvidenceMetadata(), sameDigest(), FindingPanel()

### Community 42 - "Security Service"
Cohesion: 0.13
Nodes (19): Security Service Is Sole Mutation Boundary, Security Service, Assessment Subject, Assessment Subject Sources Are Explicit and Immutable, Analyzers Read Only Content-Addressed Subject Snapshots, Subject Snapshot, Special Repository Objects Never Expand Implicitly, Security Private State Lives Under DSH Home (+11 more)

### Community 43 - "Obligations resolve as SATISFIED, NOT_APPLICABLE, or GAP"
Cohesion: 0.18
Nodes (19): Plan Amendment, Plan Amendments only add or strengthen obligations, Coverage Claims are proposals and the Kernel resolves them, Coverage Resolution, Coverage Obligation, Obligations resolve as SATISFIED, NOT_APPLICABLE, or GAP, Not Applicable Proof, NOT_APPLICABLE requires eligible negative proof (+11 more)

### Community 44 - "canonicalJson"
Cohesion: 0.20
Nodes (8): AssessmentReceiptV1, RepositoryCommandReceiptV1, RepositorySnapshotV1, canonicalJson(), checkSealReadiness(), readPublishedEvidenceSet(), digest(), RegisteredRepositoryResolution

### Community 45 - "host-repository-provider.ts"
Cohesion: 0.20
Nodes (9): repositoryBindingsV1Schema, RepositoryState, bindingIdSchema, Config, configSchema, Context, @deepseek-ai/cordis, HostRepositoryBindingV1 (+1 more)

### Community 47 - "builtin-node-package-lifecycle-analyzer.ts"
Cohesion: 0.16
Nodes (14): analyzeNodePackageInstallLifecycle(), ANALYZER_METHOD, analyzerIdentity(), analyzerIdentitySchema, BUILTIN_NODE_PACKAGE_LIFECYCLE_DESCRIPTOR, BUILTIN_NODE_PACKAGE_LIFECYCLE_QUALIFICATION, candidateSchema, hasDuplicateSecurityKey() (+6 more)

### Community 48 - "Bounded Harness Capabilities"
Cohesion: 0.14
Nodes (16): Analyzer Execution Class, Analyzer Execution Class Determines Verdict Eligibility, Bounded Harness Capabilities, v0.1 Gate-Bearing Local Analyzers Use Bounded Harness Capabilities, Model Egress Uses Minimal Redacted Source Slices, Source Slice, TS JS Node Support Uses a Hybrid Analyzer Portfolio, Hybrid Analyzer Portfolio (+8 more)

### Community 49 - "Release Conformance targets a packed fresh Harness installation"
Cohesion: 0.20
Nodes (16): Release Conformance, Release Conformance targets a packed fresh Harness installation, Reference Test Host, The Reference Test Host uses real Harness composition, Tests have no security semantic bypass, Deterministic Reference Fakes exercise official seams, Reference Fakes, The Transition Matrix receives model-based Conformance (+8 more)

### Community 50 - "AssessmentId"
Cohesion: 0.13
Nodes (14): LiveAssessmentSession, OpenAssessmentWorkbenchRequestV1, AssessmentId, RepositoryId, AssessmentListIdentityRow, DisableRepositoryPersistenceInput, SecurityPersistenceOptions, SecurityAssessmentCancellationReceiptV1 (+6 more)

### Community 51 - "assessment-list-query.ts"
Cohesion: 0.16
Nodes (12): AssessmentListItemV1, assessmentListPageV1Schema, AssessmentListAuthority, AssessmentListCursorError, AssessmentListQueryModule, authorityDigest(), cursorPayloadSchema, listKeySchema (+4 more)

### Community 52 - "Risk Decision"
Cohesion: 0.16
Nodes (15): Assessment Snapshot, Available Actions, Available Actions Are Service-Projected, Not Client-Inferred, BLOCKED Recovery View, BLOCKED View Explains Recovery Without Offering a Bypass, Evidence View Starts Redacted and Reauthorizes Sensitive Content, Evidence View, Risk Decision Form Records a Governed Immutable Decision (+7 more)

### Community 53 - "package.json"
Cohesion: 0.14
Nodes (13): description, engines, node, license, main, name, private, publishConfig (+5 more)

### Community 54 - "compilerOptions"
Cohesion: 0.14
Nodes (13): tests, ./tsconfig.json, tsdown.config.ts, vitest.config.ts, compilerOptions, allowImportingTsExtensions, declaration, declarationMap (+5 more)

### Community 55 - "security-catalog.ts"
Cohesion: 0.21
Nodes (12): CRITICAL_BREAK_GLASS_CONTROL_ID, SECURITY_ASSURANCE_PRODUCT_NAME, SecurityCatalogAssessmentModeV1, SecurityCatalogProfileV1, StartPreflightProviderV1, StartPreflightV1, builtinSupports(), MODE_DEFINITIONS (+4 more)

### Community 56 - "sealed-artifacts.ts"
Cohesion: 0.31
Nodes (13): securitySubmissionArtifactV1Schema, structuredDigest(), artifact(), assembleSealedArtifacts(), json(), publicationDirectory(), publishSealedArtifacts(), record() (+5 more)

### Community 57 - "WorkbenchPresentation"
Cohesion: 0.19
Nodes (4): CLOSED, OPEN, WorkbenchPresentation, WorkbenchPresentationSnapshotV1

### Community 58 - "Control Plane Adapter"
Cohesion: 0.21
Nodes (12): Control Plane Adapter, Control Plane Integration Is an Optional By-Value Adapter, Security Submission, Control Plane Cancellation Resolves Only an Existing Assessment, Cancellation Crash Checkpoint Preserves the Exact Assessment, Control Plane External Failure Uses Provider-Neutral Constructor, ExternalAssessmentFailureV1, Control Plane Assurance Retry Starts a Distinct Assessment (+4 more)

### Community 59 - "inject"
Cohesion: 0.17
Nodes (12): patch, immediately, inject, platform, dsh, bundle, client, @deepseek-ai/dsh-api-gateway (+4 more)

### Community 60 - "evaluateReleaseConstitutionV1"
Cohesion: 0.26
Nodes (12): aggregateReleaseCheckStatus(), assembleReleaseEvidenceManifestV1(), compareReleaseBundleReferences(), evaluateReleaseConstitutionV1(), expectedConstitutionProofStatus(), releaseCountCheckStatus(), releaseEffectivenessThresholdStatus(), releaseEvidenceManifestV1Schema (+4 more)

### Community 61 - "peerDependencies"
Cohesion: 0.20
Nodes (10): @deepseek-ai/cordis, @deepseek-ai/dsh-client-locale, @deepseek-ai/dsh-client-ui-layout, @deepseek-ai/cordis, @deepseek-ai/dsh-client-locale, @deepseek-ai/dsh-client-ui-layout, peerDependencies, @deepseek-ai/cordis (+2 more)

### Community 62 - "scripts"
Cohesion: 0.25
Nodes (8): scripts, build, pack:browser-e2e, pack:dry-run, pack:smoke, test, test:watch, typecheck

### Community 63 - ".submitAssessmentCommand"
Cohesion: 0.25
Nodes (4): isAssessmentCommandReason(), matchesAssessmentCommandReceipt(), nextAssessmentCommandIdempotencyKey(), normalizeAssessmentCommandReason()

### Community 65 - ".waitForAssessmentRevision"
Cohesion: 0.13
Nodes (12): AssessmentRevisionSignalV1, WaitForAssessmentRevisionRequest, waitUntilSealed(), repositoryFixture(), run, temporaryRoots, waitUntilState(), nodeRepositoryFixture() (+4 more)

### Community 66 - "Export Request"
Cohesion: 0.47
Nodes (6): Export UI Previews Profile and Destination While Service Performs Delivery, Export Request, Export Delivery Recovery Is Service-Owned and Bounded, Export Delivery Worker, Export Expiry Uses Two-Phase Exact-Target Reaping, Export Tombstone

### Community 67 - "generate-typert.mjs"
Cohesion: 0.33
Nodes (5): packageRoot, protocolRoot, scratchParent, syntheticPackageRoot, syntheticProtocolRoot

### Community 69 - "All Product Surfaces Share One Public Service Contract"
Cohesion: 0.50
Nodes (5): Codex Security Capability Breadth Is a Reference Envelope, Security Assessment Kernel, Assessment Engine, All Product Surfaces Share One Public Service Contract, Public Service Contract

### Community 70 - "@deepseek-ai/dsh-agent"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-agent, @deepseek-ai/dsh-agent, @deepseek-ai/dsh-agent

### Community 71 - "@deepseek-ai/dsh-api-gateway"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-api-gateway, @deepseek-ai/dsh-api-gateway, @deepseek-ai/dsh-api-gateway

### Community 72 - "@deepseek-ai/dsh-client-runtime"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-client-runtime, @deepseek-ai/dsh-client-runtime, @deepseek-ai/dsh-client-runtime

### Community 73 - "@deepseek-ai/dsh-client-ui-primitives"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-client-ui-primitives, @deepseek-ai/dsh-client-ui-primitives, @deepseek-ai/dsh-client-ui-primitives

### Community 74 - "@deepseek-ai/dsh-client-ui-sidebar"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-client-ui-sidebar, @deepseek-ai/dsh-client-ui-sidebar, @deepseek-ai/dsh-client-ui-sidebar

### Community 75 - "@deepseek-ai/dsh-client-ui-slots"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-client-ui-slots, @deepseek-ai/dsh-client-ui-slots, @deepseek-ai/dsh-client-ui-slots

### Community 76 - "@deepseek-ai/dsh-home-paths"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-home-paths, @deepseek-ai/dsh-home-paths, @deepseek-ai/dsh-home-paths

### Community 77 - "@deepseek-ai/dsh-llm"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-llm, @deepseek-ai/dsh-llm, @deepseek-ai/dsh-llm

### Community 78 - "@deepseek-ai/dsh-tools"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-tools, @deepseek-ai/dsh-tools, @deepseek-ai/dsh-tools

### Community 79 - "@deepseek-ai/dsh-typert-protocol"
Cohesion: 0.67
Nodes (3): @deepseek-ai/dsh-typert-protocol, @deepseek-ai/dsh-typert-protocol, @deepseek-ai/dsh-typert-protocol

### Community 80 - "dependencies"
Cohesion: 0.67
Nodes (3): dependencies, zod, zod

### Community 81 - "dsh-engineering-control-plane"
Cohesion: 0.67
Nodes (3): dsh-engineering-control-plane, dsh-engineering-control-plane, dsh-engineering-control-plane

### Community 82 - "react"
Cohesion: 0.67
Nodes (3): react, react, react

### Community 83 - "peerDependenciesMeta"
Cohesion: 0.67
Nodes (3): optional, peerDependenciesMeta, dsh-engineering-control-plane

### Community 89 - "evidence-view.ts"
Cohesion: 0.18
Nodes (13): EVIDENCE_VIEW_METADATA_ONLY_PROFILE_ID, EvidenceViewContentV1, EvidenceViewV1, evidenceViewV1Schema, FindingDetailViewV1, GetEvidenceViewRequest, boundedContent(), boundedJsonSchemas (+5 more)

### Community 90 - "candidate-validation.ts"
Cohesion: 0.24
Nodes (12): AnalyzerContributionV1, candidatePrefix(), CandidateValidationInputV1, json(), referenceControlState(), referenceValidationEvidenceV1Schema, sourceAnchorSchema, validateCandidate() (+4 more)

### Community 97 - "evidence-persistence.ts"
Cohesion: 0.18
Nodes (11): assessmentIdSchema, securitySubmissionJsonV1Schema, digestEnvelopeV1Schema, ExpectedProofSourceEvidence, ReleaseEvidenceVerificationInput, evidenceEnvelope(), evidenceEnvelopeV1Schema, EvidencePublicationReceiptV1 (+3 more)

### Community 98 - "external-analyzer-validation.spec.ts"
Cohesion: 0.36
Nodes (7): riskDecisionRecordV1Schema, securityAssuranceSubmissionV1Schema, run, runReferenceValidationScenario(), temporaryRoots, validationRepositoryFixture(), waitUntilAssessmentState()

### Community 99 - "host-repository-provider.spec.ts"
Cohesion: 0.32
Nodes (4): SecurityAssuranceHostRepositoryProvider, cleanRepository(), run, temporaryRoots

## Knowledge Gaps
- **679 isolated node(s):** `AirGapAccessAuditV1`, `AirGappedEvaluationAssemblyV1`, `AirGappedFindingAdjudicationV1`, `AirGappedRunnerInputV1`, `AirGappedRunnerResultV1` (+674 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **13 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `@deepseek-ai/dsh-api-gateway` connect `inject` to `workbench-remote.spec.ts`?**
  _High betweenness centrality (0.118) - this node is a cross-community bridge._
- **What connects `AirGapAccessAuditV1`, `AirGappedEvaluationAssemblyV1`, `AirGappedFindingAdjudicationV1` to the rest of the system?**
  _679 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `evaluation.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.013513513513513514 - nodes in this community are weakly interconnected._
- **Should `contracts.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.02197802197802198 - nodes in this community are weakly interconnected._
- **Should `export-delivery.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.05365296803652968 - nodes in this community are weakly interconnected._
- **Should `workbench-remote.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.06708595387840671 - nodes in this community are weakly interconnected._
- **Should `analyzer.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.07080200501253132 - nodes in this community are weakly interconnected._