from __future__ import annotations

from doc_ai_slopcheck.rules.ai_slop.ai_conversational_bleed import AiConversationalBleedRule
from doc_ai_slopcheck.rules.ai_slop.ai_hardcoded_mocks import AiHardcodedMocksRule
from doc_ai_slopcheck.rules.ai_slop.ai_identity_refusal import AiIdentityRefusalRule
from doc_ai_slopcheck.rules.ai_slop.ai_instruction_comment import AiInstructionCommentRule
from doc_ai_slopcheck.rules.ai_slop.comment_essay import CommentEssayRule
from doc_ai_slopcheck.rules.ai_slop.console_log_in_production import ConsoleLogInProductionRule
from doc_ai_slopcheck.rules.ai_slop.cross_language_idiom import CrossLanguageIdiomRule
from doc_ai_slopcheck.rules.ai_slop.dead_code_comment import DeadCodeCommentRule
from doc_ai_slopcheck.rules.ai_slop.debug_code_left import DebugCodeLeftRule
from doc_ai_slopcheck.rules.ai_slop.hallucinated_placeholder import HallucinatedPlaceholderRule
from doc_ai_slopcheck.rules.ai_slop.history_comment import HistoryCommentRule
from doc_ai_slopcheck.rules.ai_slop.incomplete_error_message import IncompleteErrorMessageRule
from doc_ai_slopcheck.rules.ai_slop.placeholder_tokens import PlaceholderTokensRule
from doc_ai_slopcheck.rules.ai_slop.plan_reference_comment import PlanReferenceCommentRule
from doc_ai_slopcheck.rules.ai_slop.stale_comment import StaleCommentRule
from doc_ai_slopcheck.rules.ai_slop.stub_function_body import StubFunctionBodyRule
from doc_ai_slopcheck.rules.ai_slop.stub_function_body_go import StubFunctionBodyGoRule
from doc_ai_slopcheck.rules.ai_slop.stub_function_body_js import StubFunctionBodyJsRule
from doc_ai_slopcheck.rules.ai_slop.stub_function_body_php import StubFunctionBodyPhpRule
from doc_ai_slopcheck.rules.ai_slop.weak_function_name import WeakFunctionNameRule
from doc_ai_slopcheck.rules.base import Rule
from doc_ai_slopcheck.rules.concurrency.global_state_leak import GlobalStateLeakRule
from doc_ai_slopcheck.rules.concurrency.go_missing_defer import GoMissingDeferRule
from doc_ai_slopcheck.rules.concurrency.js_timer_no_cleanup import JsTimerNoCleanupRule
from doc_ai_slopcheck.rules.concurrency.lock_without_release import LockWithoutReleaseRule
from doc_ai_slopcheck.rules.concurrency.thread_unsafe_global import ThreadUnsafeGlobalRule
from doc_ai_slopcheck.rules.concurrency.use_after_free import UseAfterFreeRule
from doc_ai_slopcheck.rules.error_handling.bare_except_pass import BareExceptPassRule
from doc_ai_slopcheck.rules.error_handling.bare_except_pass_go import BareExceptPassGoRule
from doc_ai_slopcheck.rules.error_handling.bare_except_pass_js import BareExceptPassJsRule
from doc_ai_slopcheck.rules.error_handling.contradictory_null_check import (
    ContradictoryNullCheckRule,
)
from doc_ai_slopcheck.rules.error_handling.division_by_zero_risk import DivisionByZeroRiskRule
from doc_ai_slopcheck.rules.error_handling.go_error_wrap_missing_w import GoErrorWrapMissingWRule
from doc_ai_slopcheck.rules.error_handling.go_ignored_error import GoIgnoredErrorRule
from doc_ai_slopcheck.rules.error_handling.js_json_parse_unguarded import JsJsonParseUnguardedRule
from doc_ai_slopcheck.rules.error_handling.js_unhandled_promise import JsUnhandledPromiseRule
from doc_ai_slopcheck.rules.error_handling.missing_default_branch import MissingDefaultBranchRule
from doc_ai_slopcheck.rules.error_handling.unreachable_code_after_return import (
    UnreachableCodeAfterReturnRule,
)
from doc_ai_slopcheck.rules.idioms.collection_modify_while_iterating import (
    CollectionModifyWhileIteratingRule,
)
from doc_ai_slopcheck.rules.idioms.js_await_in_loop import JsAwaitInLoopRule
from doc_ai_slopcheck.rules.idioms.js_loose_equality import JsLooseEqualityRule
from doc_ai_slopcheck.rules.idioms.native_alternative import NativeAlternativeRule
from doc_ai_slopcheck.rules.idioms.python_mutable_default import PythonMutableDefaultRule
from doc_ai_slopcheck.rules.idioms.react_async_useeffect import ReactAsyncUseeffectRule
from doc_ai_slopcheck.rules.idioms.react_index_key import ReactIndexKeyRule
from doc_ai_slopcheck.rules.idioms.redundant_sql_index import RedundantSqlIndexRule
from doc_ai_slopcheck.rules.idioms.select_star_sql import SelectStarSqlRule
from doc_ai_slopcheck.rules.idioms.typescript_any_abuse import TypescriptAnyAbuseRule
from doc_ai_slopcheck.rules.maintainability.assignment_in_conditional import (
    AssignmentInConditionalRule,
)
from doc_ai_slopcheck.rules.maintainability.break_in_nested_loop import BreakInNestedLoopRule
from doc_ai_slopcheck.rules.maintainability.deep_inheritance import DeepInheritanceRule
from doc_ai_slopcheck.rules.maintainability.deep_nesting import DeepNestingRule
from doc_ai_slopcheck.rules.maintainability.early_return_opportunity import (
    EarlyReturnOpportunityRule,
)
from doc_ai_slopcheck.rules.maintainability.goto_usage import GotoUsageRule
from doc_ai_slopcheck.rules.maintainability.large_anonymous_function import (
    LargeAnonymousFunctionRule,
)
from doc_ai_slopcheck.rules.maintainability.large_file import LargeFileRule
from doc_ai_slopcheck.rules.maintainability.large_function import LargeFunctionRule
from doc_ai_slopcheck.rules.maintainability.many_positional_args import ManyPositionalArgsRule
from doc_ai_slopcheck.rules.maintainability.multiple_classes_per_file import (
    MultipleClassesPerFileRule,
)
from doc_ai_slopcheck.rules.maintainability.obvious_perf_drain import ObviousPerfDrainRule
from doc_ai_slopcheck.rules.maintainability.oversized_class import OversizedClassRule
from doc_ai_slopcheck.rules.maintainability.param_reassignment import ParamReassignmentRule
from doc_ai_slopcheck.rules.maintainability.pass_through_wrapper import PassThroughWrapperRule
from doc_ai_slopcheck.rules.maintainability.recursion_without_limit import RecursionWithoutLimitRule
from doc_ai_slopcheck.rules.maintainability.short_variable_name import ShortVariableNameRule
from doc_ai_slopcheck.rules.project.api_contract_breaking import ApiContractBreakingRule
from doc_ai_slopcheck.rules.project.forbidden_import_edges import ForbiddenImportEdgesRule
from doc_ai_slopcheck.rules.project.undeclared_import import UndeclaredImportRule
from doc_ai_slopcheck.rules.project.unused_suppression import UnusedSuppressionRule
from doc_ai_slopcheck.rules.security.dangerous_shell_in_markdown import DangerousShellInMarkdownRule
from doc_ai_slopcheck.rules.security.hardcoded_secret import HardcodedSecretRule
from doc_ai_slopcheck.rules.security.idor_risk import IdorRiskRule
from doc_ai_slopcheck.rules.security.insecure_default import InsecureDefaultRule
from doc_ai_slopcheck.rules.security.js_dangerously_set_html import JsDangerouslySetHtmlRule
from doc_ai_slopcheck.rules.security.obfuscated_code import ObfuscatedCodeRule
from doc_ai_slopcheck.rules.security.php_user_input_sink import PhpUserInputSinkRule
from doc_ai_slopcheck.rules.security.regex_dos import RegexDosRule
from doc_ai_slopcheck.rules.security.sql_string_concat import SqlStringConcatRule
from doc_ai_slopcheck.rules.security.weak_hash import WeakHashRule


def build_rules() -> list[Rule]:
    """All rules, grouped like the rules/ folders. Order doesn't affect results."""
    return [
        # ai_slop
        HistoryCommentRule(),
        CommentEssayRule(),
        AiConversationalBleedRule(),
        AiHardcodedMocksRule(),
        AiIdentityRefusalRule(),
        AiInstructionCommentRule(),
        ConsoleLogInProductionRule(),
        CrossLanguageIdiomRule(),
        DeadCodeCommentRule(),
        DebugCodeLeftRule(),
        HallucinatedPlaceholderRule(),
        IncompleteErrorMessageRule(),
        PlaceholderTokensRule(),
        PlanReferenceCommentRule(),
        StaleCommentRule(),
        StubFunctionBodyGoRule(),
        StubFunctionBodyJsRule(),
        StubFunctionBodyPhpRule(),
        StubFunctionBodyRule(),
        WeakFunctionNameRule(),
        # security
        DangerousShellInMarkdownRule(),
        HardcodedSecretRule(),
        IdorRiskRule(),
        InsecureDefaultRule(),
        JsDangerouslySetHtmlRule(),
        ObfuscatedCodeRule(),
        PhpUserInputSinkRule(),
        RegexDosRule(),
        SqlStringConcatRule(),
        WeakHashRule(),
        # error_handling
        BareExceptPassGoRule(),
        BareExceptPassJsRule(),
        BareExceptPassRule(),
        ContradictoryNullCheckRule(),
        DivisionByZeroRiskRule(),
        GoErrorWrapMissingWRule(),
        GoIgnoredErrorRule(),
        JsJsonParseUnguardedRule(),
        JsUnhandledPromiseRule(),
        MissingDefaultBranchRule(),
        UnreachableCodeAfterReturnRule(),
        # concurrency
        GlobalStateLeakRule(),
        GoMissingDeferRule(),
        JsTimerNoCleanupRule(),
        LockWithoutReleaseRule(),
        ThreadUnsafeGlobalRule(),
        UseAfterFreeRule(),
        # maintainability
        PassThroughWrapperRule(),
        AssignmentInConditionalRule(),
        BreakInNestedLoopRule(),
        DeepInheritanceRule(),
        DeepNestingRule(),
        EarlyReturnOpportunityRule(),
        GotoUsageRule(),
        LargeAnonymousFunctionRule(),
        LargeFileRule(),
        LargeFunctionRule(),
        ManyPositionalArgsRule(),
        MultipleClassesPerFileRule(),
        ObviousPerfDrainRule(),
        OversizedClassRule(),
        ParamReassignmentRule(),
        RecursionWithoutLimitRule(),
        ShortVariableNameRule(),
        # idioms
        NativeAlternativeRule(),
        CollectionModifyWhileIteratingRule(),
        JsAwaitInLoopRule(),
        JsLooseEqualityRule(),
        PythonMutableDefaultRule(),
        ReactAsyncUseeffectRule(),
        ReactIndexKeyRule(),
        RedundantSqlIndexRule(),
        SelectStarSqlRule(),
        TypescriptAnyAbuseRule(),
        # project
        ApiContractBreakingRule(),
        ForbiddenImportEdgesRule(),
        UndeclaredImportRule(),
        UnusedSuppressionRule(),
    ]
