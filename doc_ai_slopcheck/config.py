from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class RuleToggle(BaseModel):
    """Config for rules whose only setting is on/off."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


# Rules with no settings beyond `enabled`. Named aliases keep the per-rule
# config names that rules and tests import.
StubFunctionBodyPhpConfig = RuleToggle
PhpUserInputSinkConfig = RuleToggle
NativeAlternativeConfig = RuleToggle
AiInstructionCommentConfig = RuleToggle
BareExceptPassConfig = RuleToggle
AiConversationalBleedConfig = RuleToggle
AiIdentityRefusalConfig = RuleToggle
IncompleteErrorMessageConfig = RuleToggle
SqlStringConcatConfig = RuleToggle
InsecureDefaultConfig = RuleToggle
HardcodedSecretConfig = RuleToggle
TypescriptAnyAbuseConfig = RuleToggle
ReactIndexKeyConfig = RuleToggle
ReactAsyncUseeffectConfig = RuleToggle
PythonMutableDefaultConfig = RuleToggle
GoMissingDeferConfig = RuleToggle
GoErrorWrapConfig = RuleToggle
CrossLanguageIdiomConfig = RuleToggle
JsAwaitInLoopConfig = RuleToggle
JsJsonParseUnguardedConfig = RuleToggle
JsUnhandledPromiseConfig = RuleToggle
JsLooseEqualityConfig = RuleToggle
JsDangerouslySetHtmlConfig = RuleToggle
SelectStarSqlConfig = RuleToggle
WeakHashConfig = RuleToggle
RegexDosConfig = RuleToggle
ObfuscatedCodeConfig = RuleToggle
GlobalStateLeakConfig = RuleToggle
UnreachableCodeAfterReturnConfig = RuleToggle
GotoUsageConfig = RuleToggle
AssignmentInConditionalConfig = RuleToggle
DebugCodeLeftConfig = RuleToggle
ContradictoryNullCheckConfig = RuleToggle
LockWithoutReleaseConfig = RuleToggle
ThreadUnsafeGlobalConfig = RuleToggle
RedundantSqlIndexConfig = RuleToggle
UseAfterFreeConfig = RuleToggle
BreakInNestedLoopConfig = RuleToggle
ApiContractBreakingConfig = RuleToggle


class PlaceholderTokensConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    banned_tokens: list[str] = Field(
        default_factory=lambda: ["TODO", "FIXME", "HACK", "TEMPORARY"]
    )


class BoundaryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_glob: str
    forbidden_prefixes: list[str] = Field(default_factory=list)
    message: str = "Forbidden import edge."


class ForbiddenImportEdgesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    boundaries: list[BoundaryConfig] = Field(default_factory=list)


class StubFunctionBodyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    excluded_function_patterns: list[str] = Field(
        default_factory=lambda: ["__init__", "setUp", "tearDown", "setUpClass", "tearDownClass"]
    )


class HallucinatedPlaceholderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    extra_patterns: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(
        default_factory=lambda: ["example.com", "example.org", "example.net"]
    )


class DeadCodeCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    min_consecutive_lines: int = 4
    excluded_paths: list[str] = Field(
        default_factory=lambda: ["docs/**", "examples/**", "*.md"]
    )


class MissingDefaultBranchConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 60% precision, fires on guard clauses
    min_elif_count: int = 2
    check_match: bool = True


class AiHardcodedMocksConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 50% precision without per-project tuning
    additional_excluded_paths: list[str] = Field(
        default_factory=lambda: ["**/seed*", "**/conftest*", "**/factory*", "**/fake*"]
    )


class UndeclaredImportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: too noisy without per-project manifest config
    additional_allowed: list[str] = Field(
        default_factory=lambda: ["typing", "typing_extensions"]
    )


class GoIgnoredErrorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    extra_allowed_patterns: list[str] = Field(default_factory=list)


class ConsoleLogConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    allowed_methods: list[str] = Field(default_factory=lambda: ["error"])


class JsTimerNoCleanupConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: fire-and-forget setTimeout for UI feedback is legitimate


class DeepNestingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 243K findings at depth=4 is too noisy
    max_depth: int = 6


class LargeFunctionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_lines: int = 150


class ObviousPerfDrainConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 37K findings is too noisy without scope analysis


class CollectionModifyWhileIteratingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False


class DivisionByZeroRiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False


class ParamReassignmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: noisy without project-specific tuning


class LargeFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in
    max_lines: int = 500


class ShortVariableNameConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: noisy
    min_length: int = 2
    allowed: list[str] = Field(
        default_factory=lambda: ["i", "j", "k", "x", "y", "z", "_", "e"]
    )


class PlanReferenceCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # Regexes matched against comment and docstring text. Add e.g.
    # r"\bD-\d+\b" to also flag decision-record IDs.
    patterns: list[str] = Field(
        default_factory=lambda: [
            r"\b(?:Task|Phase|Milestone|Sprint|Fas|Uppgift)\s+#?[A-Z]?\d+(?:\.\d+)*\b",
            # Short plan IDs; skips versions (V2), lint codes (B023), character
            # ranges ([A-Z0-9]) and dotted names (Guideline1_1.H37).
            r"(?<![-.\w])(?!V\d)[A-Z]\d{1,2}\b(?!-)",
        ]
    )
    # Real-world terms that look like plan IDs.
    ignore: list[str] = Field(
        default_factory=lambda: [
            "S3", "V8", "A4", "C4", "F1", "G1", "T4", "C89", "C99", "C11",
            "P50", "P75", "P90", "P95", "P99",
            "H1", "H2", "H3", "H4", "H5", "H6", "L1", "L2", "L3",
            "M1", "M2", "M3", "M4", "Q1", "Q2", "Q3", "Q4",
        ]
    )


class CommentEssayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    min_comment_lines: int = 15  # comment/docstring lines before a function is an essay
    max_ratio: float = 2.0  # ... and more than this many times its code lines


class HistoryCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # Case-insensitive regexes for comments narrating how the code used to be.
    # Anchored to code subjects/verbs: bare "previously"/"tidigare" mostly
    # describe runtime order ("previously set columns", "an earlier caller").
    patterns: list[str] = Field(
        default_factory=lambda: [
            r"\b(?:this|it|we|the (?:code|function|method|route|query))\s+used to\b",
            r"\bpreviously,?\s+(?:this|it|we|the (?:code|function|method|route|query))\b",
            r"\bwas (?:replaced|renamed|rewritten)\b",
            r"\bchanged (?:in|from) (?:v?\d|D-\d|PR|commit|the)\b",
            r"\bthe old (?:code|version|implementation|behaviou?r)\b",
            r"\b(?:until|fram till) (?:D-\d+|\d{4}-\d{2}-\d{2}|dess)\b",
            # Swedish
            r"\btidigare (?:form|version|implementation|kod|logik|beteende|variant)",
            r"\b(?:var|låg|bodde|hette|fanns|gjordes|skickades) (?:här )?tidigare\b",
            r"\bsom förut\b", r"\bändrat i\b", r"\bnumera\b",
        ]
    )


class PassThroughWrapperConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # opt-in: framework providers/hooks look the same


class DuplicateCodeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    min_lines: int = 10  # normalised lines: blank and comment-only lines excluded
    min_chars: int = 250  # skip windows of trivial lines (braces, short calls)


class EarlyReturnOpportunityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # Opt-in: style opinion


class RecursionWithoutLimitConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: many false positives


class DeepInheritanceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # Opt-in


class LargeAnonymousFunctionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in
    max_lines: int = 20


class StaleCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: very noisy


class IdorRiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # Opt-in low-confidence; enabled by default for awareness


class ManyPositionalArgsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_positional: int = 6  # Raised from 4: real-world codebases commonly have 5-6 args


class WeakFunctionNameConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: names like handle, process, run are standard in JS/React


class MultipleClassesPerFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # Off for Python: grouping small related classes (Pydantic models,
    # exception hierarchies) in one module is idiomatic there.
    python: bool = False


class OversizedClassConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_methods: int = 10


class DangerousShellInMarkdownConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: documentation showing dangerous commands is expected


class RulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    placeholder_tokens: PlaceholderTokensConfig = Field(default_factory=PlaceholderTokensConfig)
    forbidden_import_edges: ForbiddenImportEdgesConfig = Field(
        default_factory=ForbiddenImportEdgesConfig
    )
    stub_function_body: StubFunctionBodyConfig = Field(
        default_factory=StubFunctionBodyConfig
    )
    stub_function_body_php: StubFunctionBodyPhpConfig = Field(
        default_factory=StubFunctionBodyPhpConfig
    )
    php_user_input_sink: PhpUserInputSinkConfig = Field(
        default_factory=PhpUserInputSinkConfig
    )
    ai_instruction_comment: AiInstructionCommentConfig = Field(
        default_factory=AiInstructionCommentConfig
    )
    bare_except_pass: BareExceptPassConfig = Field(default_factory=BareExceptPassConfig)
    ai_conversational_bleed: AiConversationalBleedConfig = Field(
        default_factory=AiConversationalBleedConfig
    )
    ai_identity_refusal: AiIdentityRefusalConfig = Field(
        default_factory=AiIdentityRefusalConfig
    )
    hallucinated_placeholder: HallucinatedPlaceholderConfig = Field(
        default_factory=HallucinatedPlaceholderConfig
    )
    dead_code_comment: DeadCodeCommentConfig = Field(default_factory=DeadCodeCommentConfig)
    incomplete_error_message: IncompleteErrorMessageConfig = Field(
        default_factory=IncompleteErrorMessageConfig
    )
    missing_default_branch: MissingDefaultBranchConfig = Field(
        default_factory=MissingDefaultBranchConfig
    )
    ai_hardcoded_mocks: AiHardcodedMocksConfig = Field(
        default_factory=AiHardcodedMocksConfig
    )
    undeclared_import: UndeclaredImportConfig = Field(default_factory=UndeclaredImportConfig)
    sql_string_concat: SqlStringConcatConfig = Field(default_factory=SqlStringConcatConfig)
    insecure_default: InsecureDefaultConfig = Field(default_factory=InsecureDefaultConfig)
    hardcoded_secret: HardcodedSecretConfig = Field(default_factory=HardcodedSecretConfig)
    typescript_any_abuse: TypescriptAnyAbuseConfig = Field(
        default_factory=TypescriptAnyAbuseConfig
    )
    react_index_key: ReactIndexKeyConfig = Field(default_factory=ReactIndexKeyConfig)
    react_async_useeffect: ReactAsyncUseeffectConfig = Field(
        default_factory=ReactAsyncUseeffectConfig
    )
    go_ignored_error: GoIgnoredErrorConfig = Field(default_factory=GoIgnoredErrorConfig)
    python_mutable_default: PythonMutableDefaultConfig = Field(
        default_factory=PythonMutableDefaultConfig
    )
    go_missing_defer: GoMissingDeferConfig = Field(default_factory=GoMissingDeferConfig)
    console_log_in_production: ConsoleLogConfig = Field(default_factory=ConsoleLogConfig)
    go_error_wrap_missing_w: GoErrorWrapConfig = Field(default_factory=GoErrorWrapConfig)
    cross_language_idiom: CrossLanguageIdiomConfig = Field(
        default_factory=CrossLanguageIdiomConfig
    )
    js_await_in_loop: JsAwaitInLoopConfig = Field(default_factory=JsAwaitInLoopConfig)
    js_json_parse_unguarded: JsJsonParseUnguardedConfig = Field(
        default_factory=JsJsonParseUnguardedConfig
    )
    js_unhandled_promise: JsUnhandledPromiseConfig = Field(
        default_factory=JsUnhandledPromiseConfig
    )
    js_timer_no_cleanup: JsTimerNoCleanupConfig = Field(default_factory=JsTimerNoCleanupConfig)
    js_loose_equality: JsLooseEqualityConfig = Field(default_factory=JsLooseEqualityConfig)
    js_dangerously_set_html: JsDangerouslySetHtmlConfig = Field(
        default_factory=JsDangerouslySetHtmlConfig
    )
    deep_nesting: DeepNestingConfig = Field(default_factory=DeepNestingConfig)
    large_function: LargeFunctionConfig = Field(default_factory=LargeFunctionConfig)
    select_star_sql: SelectStarSqlConfig = Field(default_factory=SelectStarSqlConfig)
    weak_hash: WeakHashConfig = Field(default_factory=WeakHashConfig)
    regex_dos: RegexDosConfig = Field(default_factory=RegexDosConfig)
    obvious_perf_drain: ObviousPerfDrainConfig = Field(default_factory=ObviousPerfDrainConfig)
    obfuscated_code: ObfuscatedCodeConfig = Field(default_factory=ObfuscatedCodeConfig)
    global_state_leak: GlobalStateLeakConfig = Field(default_factory=GlobalStateLeakConfig)
    collection_modify_while_iterating: CollectionModifyWhileIteratingConfig = Field(
        default_factory=CollectionModifyWhileIteratingConfig
    )
    division_by_zero_risk: DivisionByZeroRiskConfig = Field(
        default_factory=DivisionByZeroRiskConfig
    )
    unreachable_code_after_return: UnreachableCodeAfterReturnConfig = Field(
        default_factory=UnreachableCodeAfterReturnConfig
    )
    param_reassignment: ParamReassignmentConfig = Field(
        default_factory=ParamReassignmentConfig
    )
    large_file: LargeFileConfig = Field(default_factory=LargeFileConfig)
    short_variable_name: ShortVariableNameConfig = Field(
        default_factory=ShortVariableNameConfig
    )
    goto_usage: GotoUsageConfig = Field(default_factory=GotoUsageConfig)
    assignment_in_conditional: AssignmentInConditionalConfig = Field(
        default_factory=AssignmentInConditionalConfig
    )
    plan_reference_comment: PlanReferenceCommentConfig = Field(
        default_factory=PlanReferenceCommentConfig
    )
    comment_essay: CommentEssayConfig = Field(default_factory=CommentEssayConfig)
    history_comment: HistoryCommentConfig = Field(default_factory=HistoryCommentConfig)
    native_alternative: NativeAlternativeConfig = Field(default_factory=NativeAlternativeConfig)
    pass_through_wrapper: PassThroughWrapperConfig = Field(
        default_factory=PassThroughWrapperConfig
    )
    duplicate_code: DuplicateCodeConfig = Field(
        default_factory=DuplicateCodeConfig
    )
    early_return_opportunity: EarlyReturnOpportunityConfig = Field(
        default_factory=EarlyReturnOpportunityConfig
    )
    recursion_without_limit: RecursionWithoutLimitConfig = Field(
        default_factory=RecursionWithoutLimitConfig
    )
    deep_inheritance: DeepInheritanceConfig = Field(default_factory=DeepInheritanceConfig)
    large_anonymous_function: LargeAnonymousFunctionConfig = Field(
        default_factory=LargeAnonymousFunctionConfig
    )
    debug_code_left: DebugCodeLeftConfig = Field(default_factory=DebugCodeLeftConfig)
    stale_comment: StaleCommentConfig = Field(default_factory=StaleCommentConfig)
    contradictory_null_check: ContradictoryNullCheckConfig = Field(
        default_factory=ContradictoryNullCheckConfig
    )
    lock_without_release: LockWithoutReleaseConfig = Field(
        default_factory=LockWithoutReleaseConfig
    )
    idor_risk: IdorRiskConfig = Field(default_factory=IdorRiskConfig)
    thread_unsafe_global: ThreadUnsafeGlobalConfig = Field(
        default_factory=ThreadUnsafeGlobalConfig
    )
    many_positional_args: ManyPositionalArgsConfig = Field(
        default_factory=ManyPositionalArgsConfig
    )
    redundant_sql_index: RedundantSqlIndexConfig = Field(
        default_factory=RedundantSqlIndexConfig
    )
    use_after_free: UseAfterFreeConfig = Field(default_factory=UseAfterFreeConfig)
    weak_function_name: WeakFunctionNameConfig = Field(
        default_factory=WeakFunctionNameConfig
    )
    multiple_classes_per_file: MultipleClassesPerFileConfig = Field(
        default_factory=MultipleClassesPerFileConfig
    )
    oversized_class: OversizedClassConfig = Field(default_factory=OversizedClassConfig)
    break_in_nested_loop: BreakInNestedLoopConfig = Field(
        default_factory=BreakInNestedLoopConfig
    )
    dangerous_shell_in_markdown: DangerousShellInMarkdownConfig = Field(
        default_factory=DangerousShellInMarkdownConfig
    )
    api_contract_breaking: ApiContractBreakingConfig = Field(
        default_factory=ApiContractBreakingConfig
    )


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ignored_paths: list[str] = Field(
        default_factory=lambda: [
            # Version control & environments
            ".git/**", ".venv/**", "**/.venv/**",
            # Build outputs
            "dist/**", "**/dist/**",
            "build/**", "**/build/**",
            ".next/**", "**/.next/**",
            # Dependencies
            "node_modules/**", "**/node_modules/**",
            "vendor/**", "**/vendor/**",
            # Drupal core and contrib (only custom code is the project's own)
            "web/core/**", "docroot/core/**", "html/core/**",
            "**/modules/contrib/**", "**/themes/contrib/**", "**/profiles/contrib/**",
            "web/libraries/**", "docroot/libraries/**", "**/sites/*/files/**",
            # Drupal scaffold copies and generated files
            "**/default.settings.php", "**/sites/example.*.php", "**/.ht.router.php",
            "web/index.php", "web/update.php", "web/autoload.php",
            "**/sites/simpletest/**", "**/.phpstorm.meta.php",
            # Generated code (incl. graphql-codegen client-preset output)
            "**/generated/**", "**/__generated__/**", "**/*.generated.*",
            "**/gql/graphql.ts", "**/gql/gql.ts", "**/gql/fragment-masking.ts",
            # Agent/CI artifacts
            "**/.claude/**", "**/worktrees/**",
            "**/swarm/runs/**", "**/agents/swarm/**",
        ]
    )
    # Skip files whose header says they are generated (@generated, DO NOT EDIT).
    skip_generated: bool = True
    # Findings in test and mock code drop one severity level (error -> warning,
    # warning -> note). Set to [] to treat test code like production code.
    test_paths: list[str] = Field(
        default_factory=lambda: [
            "tests/*", "*/tests/*", "test/*", "*/test/*", "*/__tests__/*",
            "spec/*", "*/spec/*", "mocks/*", "*/mocks/*", "*/__mocks__/*",
            "fixtures/*", "*/fixtures/*", "*/testdata/*",
            "test_*.py", "*/test_*.py", "*_test.py", "*_test.go", "conftest.py",
            "*/conftest.py", "*.test.*", "*.spec.*", "*Test.php", "*.stories.*",
        ]
    )
    rules: RulesConfig = Field(default_factory=RulesConfig)


def resolve_config_path(repo_root: Path, explicit_path: Path | None) -> Path | None:
    if explicit_path is not None:
        return explicit_path

    candidates = [
        repo_root / ".slopcheck" / "config.yaml",
        repo_root / ".slopcheck.yaml",
        repo_root / ".slopcheck.yml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def load_config(repo_root: Path, explicit_path: Path | None = None) -> AppConfig:
    config_path = resolve_config_path(repo_root, explicit_path)
    if config_path is None:
        return AppConfig()

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise SystemExit(f"slopcheck: invalid YAML in {config_path}: {exc}") from exc

    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise SystemExit(f"slopcheck: invalid config in {config_path}:\n{exc}") from exc
