"""
Public AI Data Flywheel Agent-Based Model

This ABM simulates the record-generation model from book/01i_record_generation_model.qmd.
It models how user interactions flow through stages: Eligibility → Capture → Shown Prompt →
Authorization → Transform → Publication, with explicit metadata (license, AI-use prefs, attribution).

Key components:
- User agents with different participation profiles
- Interaction events that flow through the staged pipeline
- Policy parameters (θ) that control stage-specific rates
- Multiple publication channels (git, huggingface, bluesky)
- Tracking of workflow states (open, merged, closed, tombstoned)
"""

import numpy as np
from dataclasses import dataclass, field
from typing import Literal, Dict, List, Optional, Set, Tuple, Callable
from enum import Enum
import json
from collections import defaultdict
import warnings


# Enums for model states
class Origin(Enum):
    NATURAL = "natural"
    PROMPTED = "prompted"

class RecordType(Enum):
    CHAT = "chat"
    FEEDBACK = "feedback"
    LABEL = "label"
    SUMMARY = "summary"
    RICH_DOC = "rich_doc"  # e.g., code/wiki/article created after off-platform work

class License(Enum):
    CC0 = "CC0-1.0"
    CC_BY = "CC-BY-4.0"
    CC_BY_SA = "CC-BY-SA-4.0"

class WorkflowState(Enum):
    OPEN = "open"
    MERGED = "merged"
    CLOSED = "closed"
    TOMBSTONED = "tombstoned"


class Attribution(Enum):
    USERNAME = "username"
    PSEUDONYM = "pseudonym"
    ANONYMOUS = "anonymous"


class AgentType(Enum):
    """Agent behavioral type for adversarial modeling (Extension #5)"""
    HONEST = "honest"
    SPAMMER = "spammer"
    ADVERSARIAL = "adversarial"
    LOW_EFFORT = "low_effort"


class JurisdictionType(Enum):
    """Geographic jurisdiction for compliance (Extension #12)"""
    US = "us"
    EU = "eu"
    UK = "uk"
    OTHER = "other"


@dataclass
class PolicyParams:
    """Policy parameters θ that control stage-specific rates"""
    # Base rates for each stage
    eligibility_rate: float = 1.0
    capture_rate: float = 0.9
    prompt_rate_natural: float = 0.1  # q_i for natural interactions
    prompt_rate_prompted: float = 0.8  # q_i for prompted interactions
    consent_rate_prompted: float = 0.4  # p_a when shown prompt
    consent_rate_no_prompt: float = 0.05  # p_a when not shown prompt
    transform_success_rate: float = 0.95  # p_t (PII checks, validation)

    # Channel-specific acceptance rates (p_k)
    git_merge_rate: float = 0.85
    huggingface_publish_rate: float = 0.90
    bluesky_publish_rate: float = 0.70

    # Retraction hazard rates
    retraction_hazard: float = 0.02


@dataclass
class InteractionContext:
    """Context x_i for an interaction"""
    agent_id: int
    ui_type: str
    model: str
    route: str
    timestamp: int


@dataclass
class InteractionMetadata:
    """Metadata attached to publishable records (ψ(x_i))"""
    uid: str
    record_type: RecordType
    license: License
    ai_use_pref: str
    attribution: Attribution
    attribution_name: str
    content: str
    origin: Origin
    prompt_shown: bool
    pii_flags: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            'uid': self.uid,
            'type': self.record_type.value,
            'license': self.license.value,
            'ai_use': self.ai_use_pref,
            'attribution': self.attribution_name,
            'origin': self.origin.value,
            'prompt_shown': self.prompt_shown,
            'pii_flags': self.pii_flags,
            'content_preview': self.content[:100] + '...' if len(self.content) > 100 else self.content
        }


@dataclass
class Interaction:
    """A single interaction i with its stage variables"""
    id: int
    context: InteractionContext
    origin: Origin
    record_type: RecordType

    # Stage variables (0/1 or state)
    E_i: bool = False  # Eligible
    C_i: bool = False  # Captured
    S_i: bool = False  # Shown prompt
    A_i: bool = False  # Authorized/consent
    T_i: bool = False  # Transform succeeded

    # Publication state per channel
    P_git: bool = False
    P_huggingface: bool = False
    P_bluesky: bool = False

    # Workflow states per channel
    M_git: Optional[WorkflowState] = None
    M_huggingface: Optional[WorkflowState] = None
    M_bluesky: Optional[WorkflowState] = None

    # Metadata
    metadata: Optional[InteractionMetadata] = None

    def get_stage_state(self) -> str:
        """Return current stage in pipeline"""
        if not self.E_i:
            return "ineligible"
        if not self.C_i:
            return "not_captured"
        if not self.A_i:
            return "no_consent"
        if not self.T_i:
            return "transform_failed"
        if self.P_git or self.P_huggingface or self.P_bluesky:
            return "published"
        return "awaiting_publication"


@dataclass
class UserProfile:
    """User agent with preferences and participation patterns"""
    user_id: int
    username: str

    # User preferences
    default_license: License = License.CC_BY
    ai_use_pref: str = "train-genai=n;exceptions=cc-cr"
    attribution_type: Attribution = Attribution.USERNAME

    # Behavioral parameters
    consent_propensity: float = 0.5  # Base willingness to consent
    quality_level: float = 0.7  # Affects PII likelihood, content quality
    activity_rate: float = 1.0  # Interactions per timestep

    # State tracking
    total_interactions: int = 0
    contributions_made: int = 0
    contributions_published: int = 0


class FlywheelABM:
    """Agent-based model of the Public AI Data Flywheel"""

    def __init__(self,
                 n_users: int = 100,
                 policy: Optional[PolicyParams] = None,
                 seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.policy = policy or PolicyParams()

        # Simulation state
        self.timestep = 0
        self.users: List[UserProfile] = []
        self.interactions: List[Interaction] = []
        self.interaction_counter = 0

        # Metrics tracking
        self.metrics_history = defaultdict(list)

        # Initialize users
        self._initialize_users(n_users)

    def _initialize_users(self, n_users: int):
        """Create user agents with diverse profiles"""
        for i in range(n_users):
            # Sample user characteristics
            consent_propensity = self.rng.beta(2, 2)  # Centered around 0.5
            quality_level = self.rng.beta(5, 2)  # Skewed toward higher quality
            activity_rate = self.rng.gamma(2, 0.5)  # Variable activity

            # License preferences (weighted toward CC-BY)
            license_choice = self.rng.choice(
                list(License),
                p=[0.2, 0.6, 0.2]  # CC0, CC-BY, CC-BY-SA
            )

            # Attribution preferences
            attr_choice = self.rng.choice(
                list(Attribution),
                p=[0.5, 0.3, 0.2]  # username, pseudonym, anonymous
            )

            user = UserProfile(
                user_id=i,
                username=f"user_{i}",
                default_license=license_choice,
                attribution_type=attr_choice,
                consent_propensity=consent_propensity,
                quality_level=quality_level,
                activity_rate=activity_rate
            )
            self.users.append(user)

    def step(self):
        """Execute one timestep of the simulation"""
        self.timestep += 1

        # Generate interactions from users
        new_interactions = self._generate_interactions()

        # Process each interaction through the pipeline
        for interaction in new_interactions:
            self._process_interaction_pipeline(interaction)
            self.interactions.append(interaction)

        # Process retractions for existing published items
        self._process_retractions()

        # Collect metrics
        self._collect_metrics()

    def _generate_interactions(self) -> List[Interaction]:
        """Generate new interactions based on user activity"""
        new_interactions = []

        for user in self.users:
            # Poisson-distributed interactions per user per timestep
            n_interactions = self.rng.poisson(user.activity_rate)

            for _ in range(n_interactions):
                # Decide origin (natural vs prompted)
                origin = Origin.PROMPTED if self.rng.random() < 0.2 else Origin.NATURAL

                # Decide record type (mapping-by-name to handle enum extensions robustly)
                record_type_weights = {
                    RecordType.CHAT: 0.7,
                    RecordType.FEEDBACK: 0.15,
                    RecordType.LABEL: 0.1,
                    RecordType.SUMMARY: 0.05,
                    RecordType.RICH_DOC: 0.0,  # base model does not emit rich docs by default
                }
                types = list(RecordType)
                weights = np.array([record_type_weights.get(rt, 0.0) for rt in types], dtype=float)
                if weights.sum() == 0:
                    # Fallback to uniform if misconfigured
                    weights = np.ones(len(types)) / len(types)
                else:
                    weights = weights / weights.sum()
                record_type = self.rng.choice(types, p=weights)

                # Create interaction context
                context = InteractionContext(
                    agent_id=user.user_id,
                    ui_type="openwebui",
                    model=self.rng.choice(["model_a", "model_b", "model_c"]),
                    route="standard",
                    timestamp=self.timestep
                )

                interaction = Interaction(
                    id=self.interaction_counter,
                    context=context,
                    origin=origin,
                    record_type=record_type
                )
                self.interaction_counter += 1

                user.total_interactions += 1
                new_interactions.append(interaction)

        return new_interactions

    def _process_interaction_pipeline(self, interaction: Interaction):
        """Process an interaction through the staged pipeline"""
        user = self.users[interaction.context.agent_id]

        # Stage 1: Eligibility (E_i)
        interaction.E_i = self.rng.random() < self.policy.eligibility_rate
        if not interaction.E_i:
            return

        # Stage 2: Capture (C_i)
        interaction.C_i = self.rng.random() < self.policy.capture_rate
        if not interaction.C_i:
            return

        # Stage 3: Shown prompt (S_i) - depends on origin
        prompt_rate = (self.policy.prompt_rate_prompted
                      if interaction.origin == Origin.PROMPTED
                      else self.policy.prompt_rate_natural)
        interaction.S_i = self.rng.random() < prompt_rate

        # Stage 4: Authorization/Consent (A_i) - influenced by S_i and user propensity
        base_consent_rate = (self.policy.consent_rate_prompted
                            if interaction.S_i
                            else self.policy.consent_rate_no_prompt)

        # Modulate by user's consent propensity
        consent_prob = base_consent_rate * user.consent_propensity
        interaction.A_i = self.rng.random() < consent_prob

        if not interaction.A_i:
            return

        # Create metadata for authorized interaction
        interaction.metadata = InteractionMetadata(
            uid=f"contrib_{interaction.id}",
            record_type=interaction.record_type,
            license=user.default_license,
            ai_use_pref=user.ai_use_pref,
            attribution=user.attribution_type,
            attribution_name=(user.username if user.attribution_type == Attribution.USERNAME
                            else f"anon_{user.user_id % 1000}" if user.attribution_type == Attribution.PSEUDONYM
                            else "anonymous"),
            content=f"Sample content for interaction {interaction.id}",
            origin=interaction.origin,
            prompt_shown=interaction.S_i
        )

        user.contributions_made += 1

        # Stage 5: Transform/Validation (T_i)
        # Success probability influenced by user quality
        transform_prob = self.policy.transform_success_rate * user.quality_level
        interaction.T_i = self.rng.random() < transform_prob

        if not interaction.T_i:
            # Add PII flags on failure
            interaction.metadata.pii_flags = ["potential_pii_detected"]
            return

        # Stage 6: Publication to channels (P_i^k)
        # Git/PR workflow
        if self.rng.random() < self.policy.git_merge_rate:
            interaction.P_git = True
            interaction.M_git = WorkflowState.MERGED
            user.contributions_published += 1
        else:
            interaction.M_git = WorkflowState.OPEN if self.rng.random() < 0.7 else WorkflowState.CLOSED

        # HuggingFace
        if self.rng.random() < self.policy.huggingface_publish_rate:
            interaction.P_huggingface = True
            interaction.M_huggingface = WorkflowState.MERGED

        # Bluesky (optional channel)
        if self.rng.random() < self.policy.bluesky_publish_rate:
            interaction.P_bluesky = True
            interaction.M_bluesky = WorkflowState.MERGED

    def _process_retractions(self):
        """Handle retractions/tombstoning of published items"""
        for interaction in self.interactions:
            if interaction.P_git and interaction.M_git == WorkflowState.MERGED:
                if self.rng.random() < self.policy.retraction_hazard:
                    interaction.M_git = WorkflowState.TOMBSTONED
                    interaction.P_git = False  # No longer published

    def _collect_metrics(self):
        """Collect metrics for current timestep"""
        # Count interactions in each stage
        total = len(self.interactions)
        eligible = sum(1 for i in self.interactions if i.E_i)
        captured = sum(1 for i in self.interactions if i.C_i)
        shown_prompt = sum(1 for i in self.interactions if i.S_i)
        authorized = sum(1 for i in self.interactions if i.A_i)
        transformed = sum(1 for i in self.interactions if i.T_i)

        published_git = sum(1 for i in self.interactions if i.P_git)
        published_hf = sum(1 for i in self.interactions if i.P_huggingface)
        published_bsky = sum(1 for i in self.interactions if i.P_bluesky)

        # Store metrics
        self.metrics_history['timestep'].append(self.timestep)
        self.metrics_history['total_interactions'].append(total)
        self.metrics_history['eligible'].append(eligible)
        self.metrics_history['captured'].append(captured)
        self.metrics_history['shown_prompt'].append(shown_prompt)
        self.metrics_history['authorized'].append(authorized)
        self.metrics_history['transformed'].append(transformed)
        self.metrics_history['published_git'].append(published_git)
        self.metrics_history['published_hf'].append(published_hf)
        self.metrics_history['published_bsky'].append(published_bsky)

        # Compute stage-specific rates
        if total > 0:
            self.metrics_history['p_c'].append(captured / total)
            self.metrics_history['p_a'].append(authorized / captured if captured > 0 else 0)
            self.metrics_history['p_t'].append(transformed / authorized if authorized > 0 else 0)
            self.metrics_history['p_k_git'].append(published_git / transformed if transformed > 0 else 0)

    def get_summary_stats(self) -> Dict:
        """Return summary statistics"""
        total_interactions = len(self.interactions)

        stats = {
            'timestep': self.timestep,
            'n_users': len(self.users),
            'total_interactions': total_interactions,
            'stage_counts': {
                'eligible': sum(1 for i in self.interactions if i.E_i),
                'captured': sum(1 for i in self.interactions if i.C_i),
                'shown_prompt': sum(1 for i in self.interactions if i.S_i),
                'authorized': sum(1 for i in self.interactions if i.A_i),
                'transformed': sum(1 for i in self.interactions if i.T_i),
                'published_git': sum(1 for i in self.interactions if i.P_git),
                'published_hf': sum(1 for i in self.interactions if i.P_huggingface),
                'published_bsky': sum(1 for i in self.interactions if i.P_bluesky),
            },
            'user_stats': {
                'total_contributions_made': sum(u.contributions_made for u in self.users),
                'total_contributions_published': sum(u.contributions_published for u in self.users),
                'avg_consent_propensity': np.mean([u.consent_propensity for u in self.users]),
                'avg_quality_level': np.mean([u.quality_level for u in self.users]),
            }
        }

        return stats

    def run(self, n_steps: int):
        """Run simulation for n timesteps"""
        for _ in range(n_steps):
            self.step()

    def export_sample_contributions(self, n: int = 5) -> List[Dict]:
        """Export sample published contributions for inspection"""
        published = [i for i in self.interactions
                    if i.P_git and i.metadata is not None]

        sample = self.rng.choice(published, size=min(n, len(published)), replace=False)
        return [i.metadata.to_dict() for i in sample]


if __name__ == "__main__":
    # Example usage
    print("Public AI Data Flywheel - Agent-Based Model")
    print("=" * 50)

    # Create model with default parameters
    model = FlywheelABM(n_users=100, seed=42)

    # Run for 50 timesteps
    print("\nRunning simulation for 50 timesteps...")
    model.run(50)

    # Print summary
    stats = model.get_summary_stats()
    print("\nSummary Statistics:")
    print(json.dumps(stats, indent=2))

    # Show sample contributions
    print("\nSample Published Contributions:")
    samples = model.export_sample_contributions(3)
    for i, contrib in enumerate(samples, 1):
        print(f"\n{i}. {json.dumps(contrib, indent=2)}")


"""
Extended Public AI Data Flywheel - All-in-One

The following classes implement the extended ABM in the same file as the base
model to provide a single, readable module that includes both:

- ExtendedPolicyParams: adds enable_* flags and parameters for 12 extensions
- ExtendedUserProfile: user state for learning, networks, economics, compliance
- ExtendedInteraction: interaction state for quality, privacy, governance
- ExtendedFlywheelABM: full ABM with optional extensions

See book/01i_extended_model.qmd and abms/EXTENSIONS.md for documentation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict


@dataclass
class ExtendedPolicyParams(PolicyParams):
    """
    Extended policy parameters with all 12 enhancement layers.
    Inherits from base PolicyParams. Set enable_* to False to disable features.
    """

    # ===== EXTENSION #1: TEMPORAL DYNAMICS & LEARNING =====
    enable_user_learning: bool = False  # Users update consent based on experience
    enable_system_adaptation: bool = False  # Policy θ adapts over time
    enable_reputation: bool = False  # Track and use reputation scores

    learning_rate: float = 0.05  # How fast users update beliefs (α_learn)
    reputation_decay: float = 0.01  # Reputation decay per timestep
    reputation_boost_on_publish: float = 0.1  # Reputation gain on publication
    reputation_threshold_auto_merge: float = 5.0  # Auto-merge if R_user >= threshold
    adaptation_window: int = 10  # Window for system adaptation

    # ===== EXTENSION #2: QUALITY & VALUE METRICS =====
    enable_quality_tracking: bool = False  # Track V_i (value) per contribution
    enable_composition_objectives: bool = False  # Target distributions

    quality_weight_diversity: float = 0.3  # Weight for content diversity
    quality_weight_length: float = 0.2  # Weight for content length
    quality_weight_user_reputation: float = 0.5  # Weight for user reputation
    target_license_distribution: Dict[str, float] = field(default_factory=lambda: {
        "CC0-1.0": 0.2, "CC-BY-4.0": 0.6, "CC-BY-SA-4.0": 0.2
    })

    # ===== EXTENSION #3: SOCIAL & NETWORK EFFECTS =====
    enable_network_influence: bool = False  # Peer influence on consent
    enable_coalitions: bool = False  # User coalitions
    enable_viral_prompting: bool = False  # Prompting increases after peer contributions

    network_influence_strength: float = 0.2  # How much peers affect p_a
    coalition_size_mean: float = 5.0  # Mean coalition size
    viral_prompt_boost: float = 0.05  # Increase q_i when peers contribute
    viral_prompt_decay: float = 0.9  # Decay of viral effect per timestep

    # ===== EXTENSION #4: ECONOMIC LAYER =====
    enable_rewards: bool = False  # Contributor rewards
    enable_review_costs: bool = False  # Review has cost
    enable_markets: bool = False  # Data markets

    reward_per_publication: float = 1.0  # W_i per published contribution
    review_cost_per_item: float = 0.1  # C_review(i)
    review_budget_per_step: float = 10.0  # Max review budget per timestep
    market_price_base: float = 1.0  # Base price in data market
    market_elasticity: float = 0.5  # Price response to supply/demand

    # ===== EXTENSION #5: ADVERSARIAL BEHAVIOR =====
    enable_adversarial_agents: bool = False  # Include spammers, adversaries

    adversarial_agent_fraction: float = 0.05  # % of adversarial agents
    spammer_activity_multiplier: float = 3.0  # Spammers contribute more
    adversarial_quality_penalty: float = 0.3  # Lower quality from bad actors
    gaming_detection_rate: float = 0.7  # p_t affected by behavioral patterns
    spammer_detection_threshold: int = 10  # Flag if >N low-quality in window

    # ===== EXTENSION #6: MULTI-OBJECTIVE OPTIMIZATION =====
    enable_multi_objective: bool = False  # Track Pareto frontier

    objective_weight_throughput: float = 0.4  # α
    objective_weight_quality: float = 0.3  # β
    objective_weight_diversity: float = 0.2  # γ
    objective_weight_privacy_risk: float = -0.1  # δ (negative = penalty)

    # ===== EXTENSION #7: PRIVACY & PII MODELING =====
    enable_privacy_budget: bool = False  # Differential privacy budget
    enable_pii_risk_scores: bool = False  # Risk scores instead of binary
    enable_k_anonymity: bool = False  # Minimum contributor group size

    privacy_budget_epsilon: float = 1.0  # ε for differential privacy
    privacy_budget_total: float = 100.0  # Total budget across all releases
    pii_risk_threshold: float = 0.3  # Threshold for T_i failure
    k_anonymity_minimum: int = 5  # Minimum k for releases
    pii_score_mean_honest: float = 0.1  # Mean PII score for honest users
    pii_score_std: float = 0.05  # Std dev of PII scores

    # ===== EXTENSION #8: GOVERNANCE MECHANISMS =====
    enable_voting: bool = False  # Community votes on P_i^k
    enable_appeals: bool = False  # Appeal failed T_i or P_i^k
    enable_policy_proposals: bool = False  # Users propose θ changes
    enable_quadratic_voting: bool = False  # Quadratic voting/funding

    voting_threshold: float = 0.5  # Fraction needed to approve
    appeal_success_rate: float = 0.3  # Probability appeal succeeds
    quadratic_voting_cost_k: float = 1.0  # Cost = k * votes^2
    min_voters_for_decision: int = 3  # Minimum voters needed

    # ===== EXTENSION #9: CROSS-CHANNEL DYNAMICS =====
    enable_channel_dependencies: bool = False  # Publishing to one enables others
    enable_channel_priorities: bool = False  # Prioritize certain channels
    enable_selective_disclosure: bool = False  # Different ψ per channel

    git_enables_bluesky: bool = True  # P_git → higher p_bluesky
    git_to_bluesky_boost: float = 0.2  # How much git pub boosts bluesky rate
    channel_priority_order: List[str] = field(default_factory=lambda: ["git", "huggingface", "bluesky"])

    # ===== EXTENSION #10: HETEROGENEOUS CONTRIBUTION TYPES =====
    enable_composite_contributions: bool = False  # Bundles of interactions (e.g., chat+feedback)
    enable_meta_contributions: bool = False  # Labels on others' contributions
    enable_derived_datasets: bool = False  # Aggregations, benchmarks

    composite_bundle_size_mean: float = 3.0  # Mean items per bundle
    meta_contribution_rate: float = 0.1  # Fraction of interactions that are meta
    derived_dataset_window: int = 50  # Create derived dataset every N timesteps

    # New: Type mix and dynamics
    chat_feedback_pair_rate: float = 0.2   # Given a chat, chance to also produce an immediate feedback on it
    rich_doc_project_rate: float = 0.05    # Chance that a chat seeds an off-platform rich doc project
    rich_doc_time_mean: float = 5.0        # Mean steps until rich doc completes
    rich_doc_transform_multiplier: float = 1.1  # Rich docs more likely to pass transform when authored by high-quality users
    rich_doc_git_merge_boost: float = 0.1       # Additional merge chance for rich docs
    feedback_transform_multiplier: float = 1.05 # Feedback items slightly easier to validate

    # ===== EXTENSION #11: UNCERTAINTY & EXPERIMENTATION =====
    enable_ab_testing: bool = False  # Multiple θ variants
    enable_bandits: bool = False  # Multi-armed bandit for q_i
    enable_confidence_intervals: bool = False  # Track uncertainty

    ab_test_variants: int = 1  # Number of policy variants (1 = no A/B test)
    bandit_epsilon: float = 0.1  # ε-greedy exploration rate
    confidence_level: float = 0.95  # For confidence intervals
    bandit_arms: List[float] = field(default_factory=lambda: [0.05, 0.1, 0.2, 0.3])  # prompt rates to try

    # ===== EXTENSION #12: LEGAL & COMPLIANCE =====
    enable_jurisdiction_rules: bool = False  # Geographic constraints
    enable_age_verification: bool = False  # Age < 18 check
    enable_gdpr_compliance: bool = False  # GDPR right-to-erasure tracking
    enable_license_compatibility: bool = False  # Validate L_i compatibility

    jurisdiction_restrictions: Dict[str, float] = field(default_factory=lambda: {
        "EU": 1.0, "US": 1.0, "UK": 1.0, "OTHER": 1.0
    })  # {jurisdiction: eligibility_multiplier}
    minimum_age: int = 18
    gdpr_erasure_window_days: int = 30  # Time to process erasure request
    compatible_license_pairs: Set[Tuple[str, str]] = field(default_factory=lambda: {
        ("CC0-1.0", "CC0-1.0"), ("CC0-1.0", "CC-BY-4.0"), ("CC0-1.0", "CC-BY-SA-4.0"),
        ("CC-BY-4.0", "CC-BY-4.0"), ("CC-BY-4.0", "CC-BY-SA-4.0"),
        ("CC-BY-SA-4.0", "CC-BY-SA-4.0")
    })


@dataclass
class ExtendedUserProfile(UserProfile):
    """Extended user profile with additional state for extensions"""

    # Extension #1: Learning & Reputation
    reputation: float = 0.0  # R_user(t)
    consent_history: List[bool] = field(default_factory=list)  # Track decisions
    satisfaction_history: List[float] = field(default_factory=list)  # Track outcomes

    # Extension #3: Social & Network
    network_neighbors: List[int] = field(default_factory=list)  # Connected users
    coalition_id: Optional[int] = None  # Which coalition user belongs to
    viral_boost_current: float = 0.0  # Current viral prompting boost

    # Extension #4: Economic
    total_rewards: float = 0.0  # W_total accumulated
    wallet_balance: float = 0.0  # Current balance

    # Extension #5: Adversarial
    agent_type: AgentType = AgentType.HONEST  # Behavioral type
    spam_score: float = 0.0  # Cumulative spam score
    flagged_as_adversarial: bool = False

    # Extension #8: Governance
    voting_power: float = 1.0  # Weight in votes
    governance_proposals_made: int = 0
    votes_cast: int = 0

    # Extension #11: Experimentation
    ab_test_group: int = 0  # Which experimental group

    # Extension #12: Legal/Compliance
    jurisdiction: JurisdictionType = JurisdictionType.US
    age: int = 25
    gdpr_erasure_requests: List[int] = field(default_factory=list)  # Timesteps of requests

    # Extension #10: Heterogeneous contribution types
    pending_projects: List[Dict] = field(default_factory=list)  # Each: {due, source_ids, record_type}


@dataclass
class ExtendedInteraction(Interaction):
    """Extended interaction with additional fields for extensions"""

    # Extension #2: Quality & Value
    value_score: float = 0.0  # V_i
    diversity_score: float = 0.0
    quality_dimensions: Dict[str, float] = field(default_factory=dict)

    # Extension #7: Privacy
    pii_risk_score: float = 0.0  # Continuous risk [0,1]
    privacy_cost: float = 0.0  # ε consumed

    # Extension #8: Governance
    votes_for: int = 0
    votes_against: int = 0
    appealed: bool = False
    appeal_granted: bool = False

    # Extension #9: Cross-channel
    channel_specific_metadata: Dict[str, Dict] = field(default_factory=dict)

    # Extension #10: Heterogeneous types
    is_composite: bool = False
    is_meta: bool = False  # Meta-contribution (label on another contribution)
    references: List[int] = field(default_factory=list)  # Referenced interaction IDs


class ExtendedFlywheelABM(FlywheelABM):
    """Extended ABM with all 12 enhancement layers (unified file)."""

    def __init__(self,
                 n_users: int = 100,
                 policy: Optional[ExtendedPolicyParams] = None,
                 seed: int = 42):

        # Initialize with extended policy
        self.extended_policy = policy or ExtendedPolicyParams()

        # Call parent with base policy params
        base_policy = PolicyParams(
            eligibility_rate=self.extended_policy.eligibility_rate,
            capture_rate=self.extended_policy.capture_rate,
            prompt_rate_natural=self.extended_policy.prompt_rate_natural,
            prompt_rate_prompted=self.extended_policy.prompt_rate_prompted,
            consent_rate_prompted=self.extended_policy.consent_rate_prompted,
            consent_rate_no_prompt=self.extended_policy.consent_rate_no_prompt,
            transform_success_rate=self.extended_policy.transform_success_rate,
            git_merge_rate=self.extended_policy.git_merge_rate,
            huggingface_publish_rate=self.extended_policy.huggingface_publish_rate,
            bluesky_publish_rate=self.extended_policy.bluesky_publish_rate,
            retraction_hazard=self.extended_policy.retraction_hazard
        )

        super().__init__(n_users=0, policy=base_policy, seed=seed)  # Don't init users yet

        # Extension-specific state
        self.coalitions: Dict[int, List[int]] = {}
        self.network_graph: Dict[int, Set[int]] = defaultdict(set)
        self.privacy_budget_used: float = 0.0
        self.review_budget_used: float = 0.0
        self.multi_objective_history: List[Dict[str, float]] = []
        self.ab_test_results: Dict[int, List[float]] = defaultdict(list)
        self.bandit_arm_rewards: Dict[float, List[float]] = defaultdict(list)
        self.bandit_arm_counts: Dict[float, int] = defaultdict(int)

        # Now initialize extended users
        self._initialize_extended_users(n_users)

    def _initialize_extended_users(self, n_users: int):
        """Create extended user agents"""
        self.users = []

        for i in range(n_users):
            consent_propensity = self.rng.beta(2, 2)
            quality_level = self.rng.beta(5, 2)
            activity_rate = self.rng.gamma(2, 0.5)

            license_choice = self.rng.choice(list(License), p=[0.2, 0.6, 0.2])
            attr_choice = self.rng.choice(list(Attribution), p=[0.5, 0.3, 0.2])

            if self.extended_policy.enable_adversarial_agents:
                type_roll = self.rng.random()
                if type_roll < self.extended_policy.adversarial_agent_fraction / 2:
                    agent_type = AgentType.SPAMMER
                    activity_rate *= self.extended_policy.spammer_activity_multiplier
                    quality_level *= self.extended_policy.adversarial_quality_penalty
                elif type_roll < self.extended_policy.adversarial_agent_fraction:
                    agent_type = AgentType.ADVERSARIAL
                    quality_level *= self.extended_policy.adversarial_quality_penalty
                else:
                    agent_type = AgentType.HONEST
            else:
                agent_type = AgentType.HONEST

            ab_group = i % max(1, self.extended_policy.ab_test_variants)
            jurisdiction = self.rng.choice(list(JurisdictionType))
            age = int(self.rng.normal(30, 10))
            age = max(13, min(80, age))

            user = ExtendedUserProfile(
                user_id=i,
                username=f"user_{i}",
                default_license=license_choice,
                attribution_type=attr_choice,
                consent_propensity=consent_propensity,
                quality_level=quality_level,
                activity_rate=activity_rate,
                agent_type=agent_type,
                ab_test_group=ab_group,
                jurisdiction=jurisdiction,
                age=age
            )
            self.users.append(user)

        if self.extended_policy.enable_network_influence:
            self._build_social_network()

        if self.extended_policy.enable_coalitions:
            self._form_coalitions()

    def _build_social_network(self):
        n = len(self.users)
        k = 4
        p_rewire = 0.1

        for i in range(n):
            for j in range(1, k // 2 + 1):
                neighbor = (i + j) % n
                self.network_graph[i].add(neighbor)
                self.network_graph[neighbor].add(i)
                self.users[i].network_neighbors.append(neighbor)
                self.users[neighbor].network_neighbors.append(i)

        for i in range(n):
            neighbors_copy = list(self.network_graph[i])
            for j in neighbors_copy:
                if self.rng.random() < p_rewire:
                    self.network_graph[i].discard(j)
                    self.network_graph[j].discard(i)
                    new_neighbor = self.rng.choice([u for u in range(n) if u != i and u not in self.network_graph[i]])
                    self.network_graph[i].add(new_neighbor)
                    self.network_graph[new_neighbor].add(i)

    def _form_coalitions(self):
        unassigned = list(range(len(self.users)))
        self.rng.shuffle(unassigned)
        coalition_id = 0
        while unassigned:
            size = int(self.rng.poisson(self.extended_policy.coalition_size_mean))
            size = max(1, min(size, len(unassigned)))
            members = unassigned[:size]
            unassigned = unassigned[size:]
            self.coalitions[coalition_id] = members
            for user_id in members:
                self.users[user_id].coalition_id = coalition_id
            coalition_id += 1

    def step(self):
        self.timestep += 1
        self.review_budget_used = 0.0

        if self.extended_policy.enable_bandits:
            self._bandit_select_prompt_rate()

        if self.extended_policy.enable_system_adaptation:
            self._adapt_system_policy()

        new_interactions = self._generate_interactions()
        for interaction in new_interactions:
            self._process_interaction_pipeline(interaction)
            self.interactions.append(interaction)

        if self.extended_policy.enable_viral_prompting:
            self._update_viral_effects()
        if self.extended_policy.enable_reputation:
            self._update_reputations()
        if self.extended_policy.enable_rewards:
            self._distribute_rewards()
        if self.extended_policy.enable_derived_datasets:
            if self.timestep % self.extended_policy.derived_dataset_window == 0:
                self._create_derived_dataset()

        self._process_retractions()

        if self.extended_policy.enable_multi_objective:
            self._track_multi_objective()
        self._collect_metrics()

    def _generate_interactions(self) -> List[Interaction]:
        new_interactions: List[ExtendedInteraction] = []

        # Complete due rich-doc projects
        for user in self.users:
            if not isinstance(user, ExtendedUserProfile):
                continue
            if not user.pending_projects:
                continue
            remaining = []
            for proj in user.pending_projects:
                if proj['due'] <= self.timestep:
                    context = InteractionContext(
                        agent_id=user.user_id,
                        ui_type="off_platform",
                        model="n/a",
                        route="rich_project",
                        timestamp=self.timestep
                    )
                    interaction = ExtendedInteraction(
                        id=self.interaction_counter,
                        context=context,
                        origin=Origin.NATURAL,
                        record_type=RecordType.RICH_DOC,
                        references=proj.get('source_ids', [])
                    )
                    self.interaction_counter += 1
                    new_interactions.append(interaction)
                else:
                    remaining.append(proj)
            user.pending_projects = remaining

        # Normal in-app interactions
        for user in self.users:
            n_interactions = self.rng.poisson(user.activity_rate)
            for _ in range(max(0, n_interactions)):
                origin = Origin.PROMPTED if self.rng.random() < 0.2 else Origin.NATURAL
                record_type = RecordType.CHAT
                context = InteractionContext(
                    agent_id=user.user_id,
                    ui_type="openwebui",
                    model=self.rng.choice(["model_a", "model_b", "model_c"]),
                    route="standard",
                    timestamp=self.timestep
                )
                chat_interaction = ExtendedInteraction(
                    id=self.interaction_counter,
                    context=context,
                    origin=origin,
                    record_type=record_type
                )
                self.interaction_counter += 1
                new_interactions.append(chat_interaction)

                if (
                    self.extended_policy.enable_composite_contributions
                    and self.rng.random() < self.extended_policy.chat_feedback_pair_rate
                ):
                    fb_context = InteractionContext(
                        agent_id=user.user_id,
                        ui_type="openwebui",
                        model=context.model,
                        route="feedback",
                        timestamp=self.timestep
                    )
                    feedback = ExtendedInteraction(
                        id=self.interaction_counter,
                        context=fb_context,
                        origin=origin,
                        record_type=RecordType.FEEDBACK,
                        references=[chat_interaction.id]
                    )
                    self.interaction_counter += 1
                    new_interactions.append(feedback)

                if self.rng.random() < self.extended_policy.rich_doc_project_rate:
                    delay = max(1, int(self.rng.exponential(self.extended_policy.rich_doc_time_mean)))
                    due = self.timestep + delay
                    if isinstance(user, ExtendedUserProfile):
                        user.pending_projects.append({
                            'due': due,
                            'record_type': RecordType.RICH_DOC,
                            'source_ids': [chat_interaction.id]
                        })
        return new_interactions

    def _bandit_select_prompt_rate(self):
        arms = self.extended_policy.bandit_arms
        if self.rng.random() < self.extended_policy.bandit_epsilon:
            selected_arm = self.rng.choice(arms)
        else:
            avg_rewards = {arm: (np.mean(self.bandit_arm_rewards[arm]) if self.bandit_arm_rewards[arm] else 0) for arm in arms}
            selected_arm = max(avg_rewards.keys(), key=lambda k: avg_rewards[k])
        self.policy.prompt_rate_natural = selected_arm
        self.extended_policy.prompt_rate_natural = selected_arm
        self.bandit_arm_counts[selected_arm] += 1

    def _adapt_system_policy(self):
        if self.timestep < self.extended_policy.adaptation_window:
            return
        window = self.extended_policy.adaptation_window
        recent_p_a = self.metrics_history['p_a'][-window:]
        recent_p_t = self.metrics_history['p_t'][-window:]
        if not recent_p_a or not recent_p_t:
            return
        avg_p_a = np.mean(recent_p_a)
        avg_p_t = np.mean(recent_p_t)
        if avg_p_a < 0.3 and self.policy.prompt_rate_natural < 0.5:
            self.policy.prompt_rate_natural *= 1.05
            self.extended_policy.prompt_rate_natural *= 1.05
        if avg_p_t < 0.8 and self.policy.prompt_rate_natural > 0.05:
            self.policy.prompt_rate_natural *= 0.95
            self.extended_policy.prompt_rate_natural *= 0.95

    def _update_viral_effects(self):
        for user in self.users:
            peer_contributions = 0
            for neighbor_id in user.network_neighbors:
                recent_contribs = sum(1 for i in self.interactions[-50:] if i.context.agent_id == neighbor_id and i.A_i)
                peer_contributions += recent_contribs
            if peer_contributions > 0:
                user.viral_boost_current += self.extended_policy.viral_prompt_boost * peer_contributions
            user.viral_boost_current *= self.extended_policy.viral_prompt_decay

    def _update_reputations(self):
        for user in self.users:
            user.reputation *= (1 - self.extended_policy.reputation_decay)
            user.reputation = max(0, user.reputation)
            recent_pubs = sum(1 for i in self.interactions[-10:] if i.context.agent_id == user.user_id and i.P_git)
            user.reputation += recent_pubs * self.extended_policy.reputation_boost_on_publish

    def _distribute_rewards(self):
        for user in self.users:
            pubs_this_step = sum(1 for i in self.interactions[-100:] if (i.context.agent_id == user.user_id and i.context.timestamp == self.timestep and i.P_git))
            reward = pubs_this_step * self.extended_policy.reward_per_publication
            user.total_rewards += reward
            user.wallet_balance += reward

    def _create_derived_dataset(self):
        recent_published = [i for i in self.interactions[-self.extended_policy.derived_dataset_window:] if i.P_git]
        if len(recent_published) > 10:
            pass

    def _track_multi_objective(self):
        if len(self.interactions) == 0:
            return
        throughput = sum(1 for i in self.interactions if i.P_git) / self.timestep
        published = [i for i in self.interactions if i.P_git and isinstance(i, ExtendedInteraction)]
        quality = np.mean([i.value_score for i in published]) if published else 0
        if published:
            unique_licenses = len(set(i.metadata.license for i in published if i.metadata))
            unique_attributions = len(set(i.metadata.attribution for i in published if i.metadata))
            diversity = (unique_licenses + unique_attributions) / 6
        else:
            diversity = 0
        privacy_risk = np.mean([i.pii_risk_score for i in published]) if published else 0
        objective = (
            self.extended_policy.objective_weight_throughput * throughput +
            self.extended_policy.objective_weight_quality * quality +
            self.extended_policy.objective_weight_diversity * diversity +
            self.extended_policy.objective_weight_privacy_risk * privacy_risk
        )
        self.multi_objective_history.append({
            'timestep': self.timestep,
            'throughput': throughput,
            'quality': quality,
            'diversity': diversity,
            'privacy_risk': privacy_risk,
            'objective': objective
        })

    def _process_interaction_pipeline(self, interaction):
        if not isinstance(interaction, ExtendedInteraction):
            interaction = ExtendedInteraction(
                id=interaction.id,
                context=interaction.context,
                origin=interaction.origin,
                record_type=interaction.record_type
            )

        user = self.users[interaction.context.agent_id]

        if self.extended_policy.enable_age_verification:
            if user.age < self.extended_policy.minimum_age:
                interaction.E_i = False
                return
        if self.extended_policy.enable_jurisdiction_rules:
            jurisdiction_multiplier = self.extended_policy.jurisdiction_restrictions.get(user.jurisdiction.value.upper(), 1.0)
            if self.rng.random() > jurisdiction_multiplier:
                interaction.E_i = False
                return

        interaction.E_i = self.rng.random() < self.policy.eligibility_rate
        if not interaction.E_i:
            return
        interaction.C_i = self.rng.random() < self.policy.capture_rate
        if not interaction.C_i:
            return

        prompt_rate = (self.policy.prompt_rate_prompted if interaction.origin == Origin.PROMPTED else self.policy.prompt_rate_natural)
        if self.extended_policy.enable_viral_prompting:
            if isinstance(user, ExtendedUserProfile):
                prompt_rate = min(1.0, prompt_rate + user.viral_boost_current)
        interaction.S_i = self.rng.random() < prompt_rate

        base_consent_rate = (self.policy.consent_rate_prompted if interaction.S_i else self.policy.consent_rate_no_prompt)
        consent_multiplier = user.consent_propensity
        if self.extended_policy.enable_user_learning and isinstance(user, ExtendedUserProfile) and user.satisfaction_history:
            avg_satisfaction = np.mean(user.satisfaction_history[-10:])
            learning_adjustment = self.extended_policy.learning_rate * (avg_satisfaction - 0.5)
            user.consent_propensity = float(np.clip(user.consent_propensity + learning_adjustment, 0.1, 0.9))
            consent_multiplier = user.consent_propensity
        if self.extended_policy.enable_network_influence and isinstance(user, ExtendedUserProfile):
            peer_consent_rate = np.mean([
                self.users[n_id].consent_propensity for n_id in user.network_neighbors
            ]) if user.network_neighbors else consent_multiplier
            consent_multiplier = (
                (1 - self.extended_policy.network_influence_strength) * consent_multiplier +
                self.extended_policy.network_influence_strength * peer_consent_rate
            )
        consent_prob = base_consent_rate * consent_multiplier
        interaction.A_i = self.rng.random() < consent_prob
        if isinstance(user, ExtendedUserProfile):
            user.consent_history.append(interaction.A_i)
        if not interaction.A_i:
            return

        interaction.metadata = InteractionMetadata(
            uid=f"contrib_{interaction.id}",
            record_type=interaction.record_type,
            license=user.default_license,
            ai_use_pref=user.ai_use_pref,
            attribution=user.attribution_type,
            attribution_name=(user.username if user.attribution_type == Attribution.USERNAME else f"anon_{user.user_id % 1000}" if user.attribution_type == Attribution.PSEUDONYM else "anonymous"),
            content=f"Sample content for interaction {interaction.id}",
            origin=interaction.origin,
            prompt_shown=interaction.S_i
        )
        user.contributions_made += 1

        transform_prob = self.policy.transform_success_rate * user.quality_level
        if interaction.record_type == RecordType.FEEDBACK:
            transform_prob *= self.extended_policy.feedback_transform_multiplier
        if interaction.record_type == RecordType.RICH_DOC:
            transform_prob *= self.extended_policy.rich_doc_transform_multiplier

        if self.extended_policy.enable_pii_risk_scores:
            if isinstance(user, ExtendedUserProfile) and getattr(user, 'agent_type', AgentType.HONEST) == AgentType.HONEST:
                pii_risk = max(0, self.rng.normal(self.extended_policy.pii_score_mean_honest, self.extended_policy.pii_score_std))
            else:
                pii_risk = self.rng.uniform(0.3, 0.8)
            interaction.pii_risk_score = pii_risk
            interaction.T_i = pii_risk < self.extended_policy.pii_risk_threshold
        else:
            interaction.T_i = self.rng.random() < transform_prob

        if self.extended_policy.enable_adversarial_agents and isinstance(user, ExtendedUserProfile) and getattr(user, 'agent_type', AgentType.HONEST) != AgentType.HONEST:
            recent_low_quality = sum(1 for i in self.interactions[-20:] if i.context.agent_id == user.user_id and hasattr(i, 'T_i') and not i.T_i)
            if recent_low_quality > self.extended_policy.spammer_detection_threshold:
                user.flagged_as_adversarial = True
                interaction.T_i = False

        if not interaction.T_i:
            interaction.metadata.pii_flags = ["potential_pii_detected"]
            return

        if self.extended_policy.enable_privacy_budget:
            privacy_cost = self.extended_policy.privacy_budget_epsilon * 0.1
            if self.privacy_budget_used + privacy_cost > self.extended_policy.privacy_budget_total:
                interaction.T_i = False
                return
            interaction.privacy_cost = privacy_cost
            self.privacy_budget_used += privacy_cost

        auto_merge = False
        if self.extended_policy.enable_reputation and isinstance(user, ExtendedUserProfile):
            auto_merge = user.reputation >= self.extended_policy.reputation_threshold_auto_merge

        if self.extended_policy.enable_voting and not auto_merge:
            n_voters = min(len(self.users), 10)
            voters = self.rng.choice(self.users, n_voters, replace=False)
            for voter in voters:
                vote_yes = (self.rng.random() < voter.quality_level * 0.7)
                if vote_yes:
                    interaction.votes_for += 1
                else:
                    interaction.votes_against += 1
            vote_approve = (interaction.votes_for / n_voters) >= self.extended_policy.voting_threshold
        else:
            vote_approve = True

        git_rate = self.policy.git_merge_rate if (vote_approve or auto_merge) else 0
        if interaction.record_type == RecordType.RICH_DOC:
            git_rate = min(1.0, git_rate + self.extended_policy.rich_doc_git_merge_boost)

        if self.extended_policy.enable_review_costs:
            if self.review_budget_used + self.extended_policy.review_cost_per_item > self.extended_policy.review_budget_per_step:
                git_rate *= 0.5
            else:
                self.review_budget_used += self.extended_policy.review_cost_per_item

        if self.rng.random() < git_rate:
            interaction.P_git = True
            interaction.M_git = WorkflowState.MERGED
            user.contributions_published += 1
            if isinstance(user, ExtendedUserProfile):
                user.satisfaction_history.append(0.8)
        else:
            interaction.M_git = WorkflowState.OPEN if self.rng.random() < 0.7 else WorkflowState.CLOSED
            if self.extended_policy.enable_appeals and interaction.M_git == WorkflowState.CLOSED:
                if self.rng.random() < 0.2:
                    interaction.appealed = True
                    if self.rng.random() < self.extended_policy.appeal_success_rate:
                        interaction.appeal_granted = True
                        interaction.P_git = True
                        interaction.M_git = WorkflowState.MERGED
                        user.contributions_published += 1
            if isinstance(user, ExtendedUserProfile):
                user.satisfaction_history.append(0.3)

        if self.rng.random() < self.policy.huggingface_publish_rate:
            interaction.P_huggingface = True
            interaction.M_huggingface = WorkflowState.MERGED

        bluesky_rate = self.policy.bluesky_publish_rate
        if self.extended_policy.enable_channel_dependencies and interaction.P_git:
            bluesky_rate = min(1.0, bluesky_rate + self.extended_policy.git_to_bluesky_boost)
        if self.rng.random() < bluesky_rate:
            interaction.P_bluesky = True
            interaction.M_bluesky = WorkflowState.MERGED
