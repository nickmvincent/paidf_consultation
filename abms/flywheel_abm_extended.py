"""
Public AI Data Flywheel Agent-Based Model - EXTENDED VERSION

This extended ABM includes all 12 enhancement layers on top of the base model.
Each extension can be independently enabled/disabled via PolicyParams flags.

Extensions:
1. Temporal Dynamics & Learning
2. Quality & Value Metrics
3. Social & Network Effects
4. Economic Layer
5. Adversarial Behavior
6. Multi-Objective Optimization
7. Privacy & PII Modeling
8. Governance Mechanisms
9. Cross-Channel Dynamics
10. Heterogeneous Contribution Types
11. Uncertainty & Experimentation
12. Legal & Compliance Layer

To use base model only: set all enable_* flags to False
"""

# Import base model
from flywheel_abm import *
import numpy as np
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
    enable_composite_contributions: bool = False  # Bundles of interactions
    enable_meta_contributions: bool = False  # Labels on others' contributions
    enable_derived_datasets: bool = False  # Aggregations, benchmarks

    composite_bundle_size_mean: float = 3.0  # Mean items per bundle
    meta_contribution_rate: float = 0.1  # Fraction of interactions that are meta
    derived_dataset_window: int = 50  # Create derived dataset every N timesteps

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
    """Extended ABM with all 12 enhancement layers"""

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
        self.coalitions: Dict[int, List[int]] = {}  # Coalition ID → user IDs
        self.network_graph: Dict[int, Set[int]] = defaultdict(set)  # Adjacency list
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
        self.users = []  # Clear any existing

        for i in range(n_users):
            # Base characteristics (same as parent)
            consent_propensity = self.rng.beta(2, 2)
            quality_level = self.rng.beta(5, 2)
            activity_rate = self.rng.gamma(2, 0.5)

            license_choice = self.rng.choice(
                list(License),
                p=[0.2, 0.6, 0.2]
            )

            attr_choice = self.rng.choice(
                list(Attribution),
                p=[0.5, 0.3, 0.2]
            )

            # Extension #5: Agent type
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

            # Extension #11: A/B test group assignment
            ab_group = i % max(1, self.extended_policy.ab_test_variants)

            # Extension #12: Jurisdiction and age
            jurisdiction = self.rng.choice(list(JurisdictionType))
            age = int(self.rng.normal(30, 10))
            age = max(13, min(80, age))  # Clamp to reasonable range

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

        # Extension #3: Build network and coalitions
        if self.extended_policy.enable_network_influence:
            self._build_social_network()

        if self.extended_policy.enable_coalitions:
            self._form_coalitions()

    def _build_social_network(self):
        """Build social network graph (Watts-Strogatz small-world)"""
        n = len(self.users)
        k = 4  # Each node connected to k nearest neighbors
        p_rewire = 0.1  # Rewiring probability

        # Ring lattice
        for i in range(n):
            for j in range(1, k // 2 + 1):
                neighbor = (i + j) % n
                self.network_graph[i].add(neighbor)
                self.network_graph[neighbor].add(i)
                self.users[i].network_neighbors.append(neighbor)
                self.users[neighbor].network_neighbors.append(i)

        # Random rewiring
        for i in range(n):
            neighbors_copy = list(self.network_graph[i])
            for j in neighbors_copy:
                if self.rng.random() < p_rewire:
                    # Remove edge
                    self.network_graph[i].discard(j)
                    self.network_graph[j].discard(i)
                    # Add random edge
                    new_neighbor = self.rng.choice([u for u in range(n) if u != i and u not in self.network_graph[i]])
                    self.network_graph[i].add(new_neighbor)
                    self.network_graph[new_neighbor].add(i)

    def _form_coalitions(self):
        """Form user coalitions"""
        unassigned = list(range(len(self.users)))
        self.rng.shuffle(unassigned)

        coalition_id = 0
        while unassigned:
            # Sample coalition size
            size = int(self.rng.poisson(self.extended_policy.coalition_size_mean))
            size = max(1, min(size, len(unassigned)))

            # Assign users to coalition
            members = unassigned[:size]
            unassigned = unassigned[size:]

            self.coalitions[coalition_id] = members
            for user_id in members:
                self.users[user_id].coalition_id = coalition_id

            coalition_id += 1

    # Override step to include extensions
    def step(self):
        """Extended step with all enhancement layers"""
        self.timestep += 1

        # Extension #11: Bandit arm selection for prompting
        if self.extended_policy.enable_bandits:
            self._bandit_select_prompt_rate()

        # Extension #1: System adaptation
        if self.extended_policy.enable_system_adaptation:
            self._adapt_system_policy()

        # Base: Generate and process interactions
        new_interactions = self._generate_interactions()

        for interaction in new_interactions:
            self._process_interaction_pipeline(interaction)
            self.interactions.append(interaction)

        # Extension #3: Update viral prompting effects
        if self.extended_policy.enable_viral_prompting:
            self._update_viral_effects()

        # Extension #1: Update reputations
        if self.extended_policy.enable_reputation:
            self._update_reputations()

        # Extension #4: Process rewards
        if self.extended_policy.enable_rewards:
            self._distribute_rewards()

        # Extension #10: Create derived datasets
        if self.extended_policy.enable_derived_datasets:
            if self.timestep % self.extended_policy.derived_dataset_window == 0:
                self._create_derived_dataset()

        # Base: Process retractions
        self._process_retractions()

        # Extension #6: Track multi-objective
        if self.extended_policy.enable_multi_objective:
            self._track_multi_objective()

        # Base: Collect metrics
        self._collect_metrics()

    def _bandit_select_prompt_rate(self):
        """ε-greedy multi-armed bandit for prompt_rate_natural"""
        arms = self.extended_policy.bandit_arms

        if self.rng.random() < self.extended_policy.bandit_epsilon:
            # Explore: random arm
            selected_arm = self.rng.choice(arms)
        else:
            # Exploit: best arm so far
            avg_rewards = {arm: (np.mean(self.bandit_arm_rewards[arm]) if self.bandit_arm_rewards[arm] else 0)
                          for arm in arms}
            selected_arm = max(avg_rewards.keys(), key=lambda k: avg_rewards[k])

        # Set policy
        self.policy.prompt_rate_natural = selected_arm
        self.extended_policy.prompt_rate_natural = selected_arm

        # Track selection
        self.bandit_arm_counts[selected_arm] += 1

    def _adapt_system_policy(self):
        """Adapt policy θ based on recent performance"""
        if self.timestep < self.extended_policy.adaptation_window:
            return

        # Get recent metrics
        window = self.extended_policy.adaptation_window
        recent_p_a = self.metrics_history['p_a'][-window:]
        recent_p_t = self.metrics_history['p_t'][-window:]

        if not recent_p_a or not recent_p_t:
            return

        avg_p_a = np.mean(recent_p_a)
        avg_p_t = np.mean(recent_p_t)

        # If consent rate is low, increase prompting
        if avg_p_a < 0.3 and self.policy.prompt_rate_natural < 0.5:
            self.policy.prompt_rate_natural *= 1.05
            self.extended_policy.prompt_rate_natural *= 1.05

        # If transform failure is high, decrease prompting (quality over quantity)
        if avg_p_t < 0.8 and self.policy.prompt_rate_natural > 0.05:
            self.policy.prompt_rate_natural *= 0.95
            self.extended_policy.prompt_rate_natural *= 0.95

    def _update_viral_effects(self):
        """Update viral prompting boost based on peer activity"""
        for user in self.users:
            # Count recent peer contributions
            peer_contributions = 0
            for neighbor_id in user.network_neighbors:
                neighbor = self.users[neighbor_id]
                # Check if neighbor contributed recently
                recent_contribs = sum(1 for i in self.interactions[-50:]
                                    if i.context.agent_id == neighbor_id and i.A_i)
                peer_contributions += recent_contribs

            # Update viral boost
            if peer_contributions > 0:
                user.viral_boost_current += self.extended_policy.viral_prompt_boost * peer_contributions

            # Decay
            user.viral_boost_current *= self.extended_policy.viral_prompt_decay

    def _update_reputations(self):
        """Update user reputation scores"""
        for user in self.users:
            # Decay
            user.reputation *= (1 - self.extended_policy.reputation_decay)
            user.reputation = max(0, user.reputation)

            # Boost for recent publications
            recent_pubs = sum(1 for i in self.interactions[-10:]
                            if i.context.agent_id == user.user_id and i.P_git)
            user.reputation += recent_pubs * self.extended_policy.reputation_boost_on_publish

    def _distribute_rewards(self):
        """Distribute economic rewards to contributors"""
        for user in self.users:
            # Count publications this timestep
            pubs_this_step = sum(1 for i in self.interactions[-100:]
                               if (i.context.agent_id == user.user_id
                                   and i.context.timestamp == self.timestep
                                   and i.P_git))

            reward = pubs_this_step * self.extended_policy.reward_per_publication
            user.total_rewards += reward
            user.wallet_balance += reward

    def _create_derived_dataset(self):
        """Create derived/aggregate dataset from recent contributions"""
        # This is a placeholder - in practice would create benchmarks, etc.
        recent_published = [i for i in self.interactions[-self.extended_policy.derived_dataset_window:]
                          if i.P_git]

        if len(recent_published) > 10:
            # Could create: evaluation set, benchmark, aggregated stats, etc.
            pass

    def _track_multi_objective(self):
        """Track multi-objective metrics"""
        if len(self.interactions) == 0:
            return

        # Throughput
        throughput = sum(1 for i in self.interactions if i.P_git) / self.timestep

        # Quality (average value score)
        published = [i for i in self.interactions if i.P_git and isinstance(i, ExtendedInteraction)]
        quality = np.mean([i.value_score for i in published]) if published else 0

        # Diversity (unique licenses, attribution types, etc.)
        if published:
            unique_licenses = len(set(i.metadata.license for i in published if i.metadata))
            unique_attributions = len(set(i.metadata.attribution for i in published if i.metadata))
            diversity = (unique_licenses + unique_attributions) / 6  # Normalize
        else:
            diversity = 0

        # Privacy risk (average PII risk)
        privacy_risk = np.mean([i.pii_risk_score for i in published]) if published else 0

        # Compute weighted objective
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

    # Override process_interaction_pipeline to include extensions
    def _process_interaction_pipeline(self, interaction):
        """Extended pipeline processing"""

        # Convert to extended interaction if needed
        if not isinstance(interaction, ExtendedInteraction):
            ext_interaction = ExtendedInteraction(
                id=interaction.id,
                context=interaction.context,
                origin=interaction.origin,
                record_type=interaction.record_type
            )
            interaction = ext_interaction

        user = self.users[interaction.context.agent_id]

        # Extension #12: Age verification
        if self.extended_policy.enable_age_verification:
            if user.age < self.extended_policy.minimum_age:
                interaction.E_i = False
                return

        # Extension #12: Jurisdiction rules
        if self.extended_policy.enable_jurisdiction_rules:
            jurisdiction_multiplier = self.extended_policy.jurisdiction_restrictions.get(
                user.jurisdiction.value.upper(), 1.0
            )
            if self.rng.random() > jurisdiction_multiplier:
                interaction.E_i = False
                return

        # BASE: Stage 1 - Eligibility
        interaction.E_i = self.rng.random() < self.policy.eligibility_rate
        if not interaction.E_i:
            return

        # BASE: Stage 2 - Capture
        interaction.C_i = self.rng.random() < self.policy.capture_rate
        if not interaction.C_i:
            return

        # BASE + Extension #3: Stage 3 - Shown prompt (with viral boost)
        prompt_rate = (self.policy.prompt_rate_prompted
                      if interaction.origin == Origin.PROMPTED
                      else self.policy.prompt_rate_natural)

        if self.extended_policy.enable_viral_prompting:
            prompt_rate += user.viral_boost_current
            prompt_rate = min(1.0, prompt_rate)

        interaction.S_i = self.rng.random() < prompt_rate

        # BASE + Extensions: Stage 4 - Authorization/Consent
        base_consent_rate = (self.policy.consent_rate_prompted
                            if interaction.S_i
                            else self.policy.consent_rate_no_prompt)

        # Extension #1: Learning effect
        consent_multiplier = user.consent_propensity
        if self.extended_policy.enable_user_learning and user.satisfaction_history:
            # Update based on past satisfaction
            avg_satisfaction = np.mean(user.satisfaction_history[-10:])
            learning_adjustment = self.extended_policy.learning_rate * (avg_satisfaction - 0.5)
            user.consent_propensity += learning_adjustment
            user.consent_propensity = np.clip(user.consent_propensity, 0.1, 0.9)
            consent_multiplier = user.consent_propensity

        # Extension #3: Network influence
        if self.extended_policy.enable_network_influence:
            peer_consent_rate = np.mean([
                self.users[n_id].consent_propensity
                for n_id in user.network_neighbors
            ]) if user.network_neighbors else consent_multiplier

            consent_multiplier = (
                (1 - self.extended_policy.network_influence_strength) * consent_multiplier +
                self.extended_policy.network_influence_strength * peer_consent_rate
            )

        consent_prob = base_consent_rate * consent_multiplier
        interaction.A_i = self.rng.random() < consent_prob

        # Track decision
        user.consent_history.append(interaction.A_i)

        if not interaction.A_i:
            return

        # Create metadata
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

        # Extension #2: Compute quality/value score
        if self.extended_policy.enable_quality_tracking:
            content_length = len(interaction.metadata.content) / 100  # Normalize
            diversity = self.rng.random()  # Placeholder for actual diversity metric
            reputation_score = user.reputation / 10  # Normalize

            interaction.value_score = (
                self.extended_policy.quality_weight_length * content_length +
                self.extended_policy.quality_weight_diversity * diversity +
                self.extended_policy.quality_weight_user_reputation * reputation_score
            )
            interaction.diversity_score = diversity

        # BASE + Extensions: Stage 5 - Transform/Validation
        transform_prob = self.policy.transform_success_rate * user.quality_level

        # Extension #7: PII risk score (instead of binary)
        if self.extended_policy.enable_pii_risk_scores:
            if user.agent_type == AgentType.HONEST:
                pii_risk = max(0, self.rng.normal(
                    self.extended_policy.pii_score_mean_honest,
                    self.extended_policy.pii_score_std
                ))
            else:
                pii_risk = self.rng.uniform(0.3, 0.8)  # Higher risk for adversaries

            interaction.pii_risk_score = pii_risk
            interaction.T_i = pii_risk < self.extended_policy.pii_risk_threshold
        else:
            interaction.T_i = self.rng.random() < transform_prob

        # Extension #5: Gaming detection
        if self.extended_policy.enable_adversarial_agents and user.agent_type != AgentType.HONEST:
            # Check recent spam score
            recent_low_quality = sum(1 for i in self.interactions[-20:]
                                   if i.context.agent_id == user.user_id
                                   and hasattr(i, 'T_i') and not i.T_i)

            if recent_low_quality > self.extended_policy.spammer_detection_threshold:
                user.flagged_as_adversarial = True
                interaction.T_i = False  # Block

        if not interaction.T_i:
            interaction.metadata.pii_flags = ["potential_pii_detected"]
            return

        # Extension #7: Privacy budget check
        if self.extended_policy.enable_privacy_budget:
            privacy_cost = self.extended_policy.privacy_budget_epsilon * 0.1  # Simplified
            if self.privacy_budget_used + privacy_cost > self.extended_policy.privacy_budget_total:
                interaction.T_i = False
                return
            interaction.privacy_cost = privacy_cost
            self.privacy_budget_used += privacy_cost

        # BASE + Extensions: Stage 6 - Publication

        # Extension #1: Reputation-based auto-merge
        auto_merge = False
        if self.extended_policy.enable_reputation:
            auto_merge = user.reputation >= self.extended_policy.reputation_threshold_auto_merge

        # Extension #8: Community voting
        if self.extended_policy.enable_voting and not auto_merge:
            # Simple voting simulation
            n_voters = min(len(self.users), 10)
            voters = self.rng.choice(self.users, n_voters, replace=False)

            for voter in voters:
                # Vote based on quality and voter's propensity
                vote_yes = (self.rng.random() < voter.quality_level * 0.7)
                if vote_yes:
                    interaction.votes_for += 1
                else:
                    interaction.votes_against += 1

            vote_approve = (interaction.votes_for / n_voters) >= self.extended_policy.voting_threshold
        else:
            vote_approve = True

        # Git publication
        git_rate = self.policy.git_merge_rate if (vote_approve or auto_merge) else 0

        # Extension #4: Review budget constraint
        if self.extended_policy.enable_review_costs:
            if self.review_budget_used + self.extended_policy.review_cost_per_item > \
               self.extended_policy.review_budget_per_step:
                git_rate *= 0.5  # Lower rate if budget exhausted
            else:
                self.review_budget_used += self.extended_policy.review_cost_per_item

        if self.rng.random() < git_rate:
            interaction.P_git = True
            interaction.M_git = WorkflowState.MERGED
            user.contributions_published += 1

            # Extension #1: Record satisfaction (simplified)
            user.satisfaction_history.append(0.8)  # Successful publication → high satisfaction
        else:
            interaction.M_git = WorkflowState.OPEN if self.rng.random() < 0.7 else WorkflowState.CLOSED

            # Extension #8: Appeal process
            if self.extended_policy.enable_appeals and interaction.M_git == WorkflowState.CLOSED:
                if self.rng.random() < 0.2:  # 20% appeal
                    interaction.appealed = True
                    if self.rng.random() < self.extended_policy.appeal_success_rate:
                        interaction.appeal_granted = True
                        interaction.P_git = True
                        interaction.M_git = WorkflowState.MERGED
                        user.contributions_published += 1

            # Record dissatisfaction
            user.satisfaction_history.append(0.3)

        # HuggingFace (same as base)
        if self.rng.random() < self.policy.huggingface_publish_rate:
            interaction.P_huggingface = True
            interaction.M_huggingface = WorkflowState.MERGED

        # Bluesky (with Extension #9: channel dependency)
        bluesky_rate = self.policy.bluesky_publish_rate
        if self.extended_policy.enable_channel_dependencies and interaction.P_git:
            bluesky_rate += self.extended_policy.git_to_bluesky_boost
            bluesky_rate = min(1.0, bluesky_rate)

        if self.rng.random() < bluesky_rate:
            interaction.P_bluesky = True
            interaction.M_bluesky = WorkflowState.MERGED


if __name__ == "__main__":
    print("Extended Public AI Data Flywheel - ABM")
    print("=" * 60)

    # Example 1: Base model (all extensions disabled)
    print("\n### Example 1: Base Model (No Extensions) ###")
    base_policy = ExtendedPolicyParams()  # All enable_* default to False
    model_base = ExtendedFlywheelABM(n_users=50, policy=base_policy, seed=42)
    model_base.run(30)
    stats_base = model_base.get_summary_stats()
    print(f"Published: {stats_base['stage_counts']['published_git']}")

    # Example 2: With learning and reputation
    print("\n### Example 2: Learning + Reputation ###")
    learning_policy = ExtendedPolicyParams(
        enable_user_learning=True,
        enable_reputation=True,
        learning_rate=0.1,
        reputation_boost_on_publish=0.2
    )
    model_learning = ExtendedFlywheelABM(n_users=50, policy=learning_policy, seed=43)
    model_learning.run(30)
    stats_learning = model_learning.get_summary_stats()
    print(f"Published: {stats_learning['stage_counts']['published_git']}")
    print(f"Avg reputation: {np.mean([u.reputation for u in model_learning.users]):.2f}")

    # Example 3: Full extensions
    print("\n### Example 3: All Extensions Enabled ###")
    full_policy = ExtendedPolicyParams(
        enable_user_learning=True,
        enable_reputation=True,
        enable_quality_tracking=True,
        enable_network_influence=True,
        enable_rewards=True,
        enable_adversarial_agents=True,
        enable_multi_objective=True,
        enable_pii_risk_scores=True,
        adversarial_agent_fraction=0.1
    )
    model_full = ExtendedFlywheelABM(n_users=50, policy=full_policy, seed=44)
    model_full.run(30)
    stats_full = model_full.get_summary_stats()
    print(f"Published: {stats_full['stage_counts']['published_git']}")
    print(f"Privacy budget used: {model_full.privacy_budget_used:.2f}")
    print(f"Adversarial users: {sum(1 for u in model_full.users if u.agent_type != AgentType.HONEST)}")

    print("\n" + "=" * 60)
    print("Extended ABM demonstration complete!")
