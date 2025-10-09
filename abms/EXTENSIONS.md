# Extended Flywheel ABM - Feature Documentation

This document describes all 12 enhancement layers added to the base Public AI Data Flywheel ABM.

## Quick Start

```python
from flywheel_abm_extended import ExtendedFlywheelABM, ExtendedPolicyParams

# Use base model (all extensions OFF)
policy = ExtendedPolicyParams()
model = ExtendedFlywheelABM(n_users=100, policy=policy, seed=42)
model.run(50)

# Enable specific extensions
policy_with_learning = ExtendedPolicyParams(
    enable_user_learning=True,
    enable_reputation=True,
    learning_rate=0.1
)
model_learning = ExtendedFlywheelABM(n_users=100, policy=policy_with_learning)
model_learning.run(50)
```

---

## Extension #1: Temporal Dynamics & Learning

**Purpose**: Model how users and the system adapt over time based on experience.

### Features
- **User Learning**: `consent_propensity` updates based on satisfaction history
- **System Adaptation**: Policy θ adjusts based on recent performance
- **Reputation**: Users build reputation capital that affects merge rates

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_user_learning` | bool | False | Enable consent propensity learning |
| `enable_system_adaptation` | bool | False | Enable adaptive policy θ(t) |
| `enable_reputation` | bool | False | Track reputation scores |
| `learning_rate` | float | 0.05 | α_learn: how fast beliefs update |
| `reputation_decay` | float | 0.01 | Per-timestep reputation decay |
| `reputation_boost_on_publish` | float | 0.1 | Reputation gain per publication |
| `reputation_threshold_auto_merge` | float | 5.0 | Auto-merge if R_user ≥ threshold |
| `adaptation_window` | int | 10 | Window for computing adaptation |

### Formal Model

**User Learning**:
```
p_a(i, t) = p_a(i, t-1) + α_learn · (satisfaction_{t-1} - 0.5)
```

**Reputation**:
```
R_user(t) = R_user(t-1) · (1 - δ_decay) + β_pub · 1[published_{t}]
```

**Auto-merge**:
```
p_k(i) = 1 if R_user ≥ τ_auto, else base_p_k
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_user_learning=True,
    enable_reputation=True,
    learning_rate=0.1,  # Fast learning
    reputation_threshold_auto_merge=3.0  # Lower threshold
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(100)

# Inspect reputation distribution
reputations = [u.reputation for u in model.users]
print(f"Avg reputation: {np.mean(reputations):.2f}")
print(f"Max reputation: {np.max(reputations):.2f}")

# Check learning effects
for user in sorted(model.users, key=lambda u: u.reputation, reverse=True)[:5]:
    print(f"{user.username}: R={user.reputation:.2f}, consent={user.consent_propensity:.2f}")
```

---

## Extension #2: Quality & Value Metrics

**Purpose**: Track contribution value V_i and optimize for dataset composition.

### Features
- **Value Scoring**: Compute V_i per contribution
- **Composition Objectives**: Target distributions (e.g., license mix)
- **Quality-adjusted Throughput**: Λ_k^Q = E[∑ V_i · P_i^k]

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_quality_tracking` | bool | False | Compute V_i scores |
| `enable_composition_objectives` | bool | False | Track target distributions |
| `quality_weight_diversity` | float | 0.3 | Weight for content diversity |
| `quality_weight_length` | float | 0.2 | Weight for length |
| `quality_weight_user_reputation` | float | 0.5 | Weight for reputation |
| `target_license_distribution` | Dict | {CC0: 0.2, BY: 0.6, SA: 0.2} | Target % per license |

### Formal Model

```
V_i = w_div · diversity_i + w_len · length_i + w_rep · (R_user / 10)
Λ_k^Q = (1/T) · ∑_{t=1}^T ∑_{i: P_i^k=1} V_i
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_quality_tracking=True,
    enable_reputation=True,  # Needed for reputation-based quality
    quality_weight_diversity=0.5,
    quality_weight_length=0.2,
    quality_weight_user_reputation=0.3
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Analyze quality
published = [i for i in model.interactions if i.P_git and hasattr(i, 'value_score')]
if published:
    values = [i.value_score for i in published]
    print(f"Avg value: {np.mean(values):.3f}")
    print(f"Total value: {np.sum(values):.2f}")
```

---

## Extension #3: Social & Network Effects

**Purpose**: Model peer influence, coalitions, and viral dynamics.

### Features
- **Network Influence**: Neighbors affect consent decisions
- **Coalitions**: Users form groups for collective action
- **Viral Prompting**: Prompting increases when peers contribute

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_network_influence` | bool | False | Peer influence on p_a |
| `enable_coalitions` | bool | False | Form user coalitions |
| `enable_viral_prompting` | bool | False | Viral boost to q_i |
| `network_influence_strength` | float | 0.2 | How much peers matter |
| `coalition_size_mean` | float | 5.0 | Mean coalition size |
| `viral_prompt_boost` | float | 0.05 | Boost per peer contribution |
| `viral_prompt_decay` | float | 0.9 | Decay of viral effect |

### Formal Model

**Network Influence**:
```
p_a(i) = (1-γ) · p_a_base(i) + γ · mean(p_a_neighbors)
```

**Viral Prompting**:
```
q_i(t) = q_base + viral_boost(t)
viral_boost(t) = viral_boost(t-1) · decay + β · count(peer_contributions)
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_network_influence=True,
    enable_viral_prompting=True,
    network_influence_strength=0.3,  # Strong peer effect
    viral_prompt_boost=0.1
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Inspect network structure
print(f"Coalitions formed: {len(model.coalitions)}")
for cid, members in list(model.coalitions.items())[:3]:
    print(f"  Coalition {cid}: {len(members)} members")
```

---

## Extension #4: Economic Layer

**Purpose**: Model incentives, costs, and markets.

### Features
- **Contributor Rewards**: W_i per publication
- **Review Costs**: C_review(i) affects throughput
- **Data Markets**: Price dynamics based on supply/demand

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_rewards` | bool | False | Distribute rewards |
| `enable_review_costs` | bool | False | Review has cost |
| `enable_markets` | bool | False | Data market dynamics |
| `reward_per_publication` | float | 1.0 | W_i per publish |
| `review_cost_per_item` | float | 0.1 | C_review(i) |
| `review_budget_per_step` | float | 10.0 | Max budget/step |
| `market_price_base` | float | 1.0 | Base market price |
| `market_elasticity` | float | 0.5 | Price elasticity |

### Formal Model

```
W_total(user) = ∑_{i: author=user, P_i=1} reward_per_pub
Budget_used(t) = ∑_{i ∈ t} C_review(i)
p_k(i) = p_k_base · min(1, Budget_remain / C_review(i))
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_rewards=True,
    enable_review_costs=True,
    reward_per_publication=2.0,
    review_budget_per_step=15.0
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Check earnings
top_earners = sorted(model.users, key=lambda u: u.total_rewards, reverse=True)[:5]
for user in top_earners:
    print(f"{user.username}: {user.total_rewards:.2f} earned, "
          f"{user.contributions_published} published")
```

---

## Extension #5: Adversarial Behavior

**Purpose**: Model spammers, low-quality actors, and gaming detection.

### Features
- **Agent Types**: HONEST, SPAMMER, ADVERSARIAL, LOW_EFFORT
- **Gaming Detection**: Behavioral pattern analysis
- **Quality Penalties**: Lower transform success for bad actors

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_adversarial_agents` | bool | False | Include adversaries |
| `adversarial_agent_fraction` | float | 0.05 | % adversarial |
| `spammer_activity_multiplier` | float | 3.0 | Spammers contribute more |
| `adversarial_quality_penalty` | float | 0.3 | Quality penalty |
| `gaming_detection_rate` | float | 0.7 | Detection probability |
| `spammer_detection_threshold` | int | 10 | Flag if >N low-quality |

### Formal Model

```
τ_user ∈ {HONEST, SPAMMER, ADVERSARIAL}
activity(user) = activity_base · (multiplier if τ=SPAMMER else 1)
p_t(i | τ=ADVERSARIAL) = p_t_base · (1 - penalty)
flagged = 1 if count_low_quality(recent) > threshold
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_adversarial_agents=True,
    adversarial_agent_fraction=0.15,  # 15% adversarial
    gaming_detection_rate=0.8
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Analyze adversarial impact
adversaries = [u for u in model.users if u.agent_type != AgentType.HONEST]
honest = [u for u in model.users if u.agent_type == AgentType.HONEST]

print(f"Adversarial users: {len(adversaries)}")
print(f"Avg pub (adversarial): {np.mean([u.contributions_published for u in adversaries]):.2f}")
print(f"Avg pub (honest): {np.mean([u.contributions_published for u in honest]):.2f}")
print(f"Flagged: {sum(1 for u in model.users if u.flagged_as_adversarial)}")
```

---

## Extension #6: Multi-Objective Optimization

**Purpose**: Explicitly track throughput-quality-diversity-privacy tradeoffs.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_multi_objective` | bool | False | Track Pareto metrics |
| `objective_weight_throughput` | float | 0.4 | α (throughput) |
| `objective_weight_quality` | float | 0.3 | β (quality) |
| `objective_weight_diversity` | float | 0.2 | γ (diversity) |
| `objective_weight_privacy_risk` | float | -0.1 | δ (privacy penalty) |

### Formal Model

```
Objective(t) = α·Throughput + β·Quality + γ·Diversity + δ·Privacy_Risk
where:
  Throughput = |{i: P_i=1}| / t
  Quality = mean(V_i for published)
  Diversity = unique_licenses + unique_attributions
  Privacy_Risk = mean(PII_risk_i)
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_multi_objective=True,
    enable_quality_tracking=True,  # Needed
    enable_pii_risk_scores=True,   # Needed
    objective_weight_throughput=0.3,
    objective_weight_quality=0.5,
    objective_weight_diversity=0.3,
    objective_weight_privacy_risk=-0.1
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Plot Pareto frontier
for record in model.multi_objective_history[-10:]:
    print(f"t={record['timestep']}: "
          f"throughput={record['throughput']:.3f}, "
          f"quality={record['quality']:.3f}, "
          f"objective={record['objective']:.3f}")
```

---

## Extension #7: Privacy & PII Modeling

**Purpose**: Model privacy budgets, risk scores, and k-anonymity.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_privacy_budget` | bool | False | ε-DP budget tracking |
| `enable_pii_risk_scores` | bool | False | Continuous risk scores |
| `enable_k_anonymity` | bool | False | Minimum group size |
| `privacy_budget_epsilon` | float | 1.0 | ε per release |
| `privacy_budget_total` | float | 100.0 | Total budget |
| `pii_risk_threshold` | float | 0.3 | Threshold for T_i |
| `k_anonymity_minimum` | int | 5 | Minimum k |
| `pii_score_mean_honest` | float | 0.1 | Mean PII for honest |

### Formal Model

```
Budget_used = ∑_i ε_i
T_i = 0 if (Budget_used + ε_i > Budget_total) OR (risk_i > τ)
risk_i ~ N(μ_honest, σ) if τ=HONEST
       ~ U(0.3, 0.8) if τ=ADVERSARIAL
k-anonymity: only release if |contributors_in_batch| ≥ k
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_privacy_budget=True,
    enable_pii_risk_scores=True,
    privacy_budget_total=50.0,  # Tight budget
    pii_risk_threshold=0.2       # Strict threshold
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

print(f"Privacy budget used: {model.privacy_budget_used:.2f} / "
      f"{policy.privacy_budget_total}")

published = [i for i in model.interactions if i.P_git and hasattr(i, 'pii_risk_score')]
if published:
    risks = [i.pii_risk_score for i in published]
    print(f"Avg PII risk (published): {np.mean(risks):.3f}")
```

---

## Extension #8: Governance Mechanisms

**Purpose**: Community voting, appeals, and policy proposals.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_voting` | bool | False | Community votes on P_i^k |
| `enable_appeals` | bool | False | Appeal rejections |
| `enable_policy_proposals` | bool | False | Users propose θ changes |
| `enable_quadratic_voting` | bool | False | Quadratic voting |
| `voting_threshold` | float | 0.5 | Approval threshold |
| `appeal_success_rate` | float | 0.3 | P(appeal granted) |
| `min_voters_for_decision` | int | 3 | Min voters |

### Formal Model

```
v_i = ∑_j w_j · vote_j(i)
P_i^k = 1 if v_i / |voters| ≥ τ_vote
Appeal: if M_i=CLOSED, retry with P(success)=p_appeal
Quadratic: cost(n_votes) = k · n^2
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_voting=True,
    enable_appeals=True,
    voting_threshold=0.6,  # Require 60% approval
    appeal_success_rate=0.4
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Check voting stats
appeals = [i for i in model.interactions if hasattr(i, 'appealed') and i.appealed]
appeals_granted = [i for i in appeals if i.appeal_granted]
print(f"Appeals: {len(appeals)}, Granted: {len(appeals_granted)}")
```

---

## Extension #9: Cross-Channel Dynamics

**Purpose**: Model channel dependencies and priorities.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_channel_dependencies` | bool | False | P_git → boost P_bluesky |
| `enable_channel_priorities` | bool | False | Prioritize channels |
| `enable_selective_disclosure` | bool | False | Different ψ per channel |
| `git_enables_bluesky` | bool | True | Dependency flag |
| `git_to_bluesky_boost` | float | 0.2 | Boost amount |

### Formal Model

```
p_bluesky(i) = p_bluesky_base + β_boost · 1[P_git(i)] if dependencies enabled
Priority: process channels in order [git, hf, bluesky]
```

### Example

```python
policy = ExtendedPolicyParams(
    enable_channel_dependencies=True,
    git_to_bluesky_boost=0.3  # 30% boost
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

git_pubs = [i for i in model.interactions if i.P_git]
bsky_pubs = [i for i in model.interactions if i.P_bluesky]
both = [i for i in model.interactions if i.P_git and i.P_bluesky]

print(f"Git: {len(git_pubs)}, Bluesky: {len(bsky_pubs)}, Both: {len(both)}")
print(f"Bluesky given Git: {len(both) / len(git_pubs) if git_pubs else 0:.2%}")
```

---

## Extension #10: Heterogeneous Contribution Types

**Purpose**: Model bundles, meta-contributions, derived datasets.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_composite_contributions` | bool | False | Bundles |
| `enable_meta_contributions` | bool | False | Labels on others' work |
| `enable_derived_datasets` | bool | False | Aggregations |
| `composite_bundle_size_mean` | float | 3.0 | Bundle size |
| `meta_contribution_rate` | float | 0.1 | % meta |
| `derived_dataset_window` | int | 50 | Create every N steps |

---

## Extension #11: Uncertainty & Experimentation

**Purpose**: A/B testing, multi-armed bandits, confidence intervals.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_ab_testing` | bool | False | Split users into variants |
| `enable_bandits` | bool | False | ε-greedy for prompt rates |
| `enable_confidence_intervals` | bool | False | Track uncertainty |
| `ab_test_variants` | int | 1 | # variants |
| `bandit_epsilon` | float | 0.1 | Exploration rate |
| `bandit_arms` | List[float] | [0.05,0.1,0.2,0.3] | Prompt rates to try |

### Example

```python
policy = ExtendedPolicyParams(
    enable_bandits=True,
    bandit_epsilon=0.2,  # 20% exploration
    bandit_arms=[0.05, 0.1, 0.15, 0.25, 0.4]
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(100)

print("Bandit arm selections:")
for arm, count in model.bandit_arm_counts.items():
    print(f"  Rate {arm}: {count} times")
```

---

## Extension #12: Legal & Compliance

**Purpose**: Jurisdiction rules, age verification, GDPR, license compatibility.

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_jurisdiction_rules` | bool | False | Geographic constraints |
| `enable_age_verification` | bool | False | Age < 18 blocked |
| `enable_gdpr_compliance` | bool | False | Erasure tracking |
| `enable_license_compatibility` | bool | False | Validate compatibility |
| `jurisdiction_restrictions` | Dict | {...} | Eligibility by jurisdiction |
| `minimum_age` | int | 18 | Age threshold |
| `gdpr_erasure_window_days` | int | 30 | Days to process |

### Example

```python
policy = ExtendedPolicyParams(
    enable_jurisdiction_rules=True,
    enable_age_verification=True,
    jurisdiction_restrictions={"EU": 1.0, "US": 1.0, "OTHER": 0.5},
    minimum_age=18
)

model = ExtendedFlywheelABM(n_users=100, policy=policy)
model.run(50)

# Check compliance
underage = [u for u in model.users if u.age < policy.minimum_age]
print(f"Underage users: {len(underage)} (blocked from contributing)")
```

---

## Combined Example: Realistic Public AI Scenario

```python
# Public AI flywheel with key features enabled
policy = ExtendedPolicyParams(
    # Learning & adaptation
    enable_user_learning=True,
    enable_reputation=True,
    enable_system_adaptation=True,
    learning_rate=0.08,

    # Quality & privacy
    enable_quality_tracking=True,
    enable_pii_risk_scores=True,
    pii_risk_threshold=0.25,

    # Social dynamics
    enable_network_influence=True,
    enable_viral_prompting=True,

    # Governance
    enable_voting=True,
    enable_appeals=True,
    voting_threshold=0.55,

    # Adversarial resilience
    enable_adversarial_agents=True,
    adversarial_agent_fraction=0.08,
    gaming_detection_rate=0.75,

    # Compliance
    enable_age_verification=True,
    enable_gdpr_compliance=True,

    # Objectives
    enable_multi_objective=True,
    objective_weight_throughput=0.25,
    objective_weight_quality=0.40,
    objective_weight_diversity=0.25,
    objective_weight_privacy_risk=-0.10
)

model = ExtendedFlywheelABM(n_users=200, policy=policy, seed=42)
model.run(100)

# Comprehensive analysis
stats = model.get_summary_stats()
print(f"Published: {stats['stage_counts']['published_git']}")
print(f"Avg reputation: {np.mean([u.reputation for u in model.users]):.2f}")
print(f"Privacy budget: {model.privacy_budget_used:.2f}")
print(f"Multi-objective score: {model.multi_objective_history[-1]['objective']:.3f}")
```

---

## Next Steps

After implementing all extensions in the ABM, we'll sync the formal model text in `book/01i_record_generation_model.qmd` to document the mathematical foundations.
