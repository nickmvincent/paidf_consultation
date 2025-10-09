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
from typing import Literal, Dict, List, Optional, Set
from enum import Enum
import json
from collections import defaultdict


# Enums for model states
class Origin(Enum):
    NATURAL = "natural"
    PROMPTED = "prompted"


class RecordType(Enum):
    CHAT = "chat"
    FEEDBACK = "feedback"
    LABEL = "label"
    SUMMARY = "summary"


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

                # Decide record type
                record_type = self.rng.choice(
                    list(RecordType),
                    p=[0.7, 0.15, 0.1, 0.05]  # mostly chats
                )

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
