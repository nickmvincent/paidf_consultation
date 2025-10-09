"""
Example: Interactive Flywheel Exploration

This script demonstrates common analysis patterns for the Flywheel ABM.
Can be converted to a Jupyter notebook or run directly.
"""

from flywheel_abm import FlywheelABM, PolicyParams, License, Attribution
from interactive_viz import FlywheelViz
import matplotlib.pyplot as plt
import numpy as np
import json


def example_1_basic_simulation():
    """Example 1: Run a basic simulation and inspect results"""
    print("\n" + "=" * 70)
    print("EXAMPLE 1: Basic Simulation")
    print("=" * 70)

    # Create and run model
    model = FlywheelABM(n_users=100, seed=42)
    model.run(50)

    # Get summary statistics
    stats = model.get_summary_stats()

    print(f"\nSimulation completed: {stats['timestep']} timesteps")
    print(f"Total interactions: {stats['total_interactions']:,}")
    print(f"\nStage breakdown:")
    for stage, count in stats['stage_counts'].items():
        print(f"  {stage:20s}: {count:6,}")

    print(f"\nOverall conversion rate: "
          f"{stats['stage_counts']['published_git'] / stats['total_interactions'] * 100:.2f}%")

    print(f"\nUser statistics:")
    print(f"  Avg consent propensity: {stats['user_stats']['avg_consent_propensity']:.3f}")
    print(f"  Avg quality level: {stats['user_stats']['avg_quality_level']:.3f}")

    # Show sample contributions
    print("\nSample published contributions:")
    samples = model.export_sample_contributions(3)
    for i, contrib in enumerate(samples, 1):
        print(f"\n  {i}. {contrib['uid']}")
        print(f"     License: {contrib['license']}")
        print(f"     AI-use: {contrib['ai_use']}")
        print(f"     Attribution: {contrib['attribution']}")
        print(f"     Content: {contrib['content_preview']}")

    return model


def example_2_visualizations():
    """Example 2: Create visualizations"""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Visualizations")
    print("=" * 70)

    # Run model
    model = FlywheelABM(n_users=150, seed=43)
    model.run(75)
    viz = FlywheelViz(model)

    # Create multiple plots
    print("\nGenerating visualizations...")

    # 1. Funnel chart
    print("  - Conversion funnel")
    viz.plot_funnel()

    # 2. Time series
    print("  - Time series metrics")
    viz.plot_time_series()

    # 3. User distributions
    print("  - User characteristic distributions")
    viz.plot_user_distributions()

    # 4. License breakdown
    print("  - License and attribution breakdown")
    viz.plot_license_breakdown()

    # 5. Comprehensive dashboard
    print("  - Comprehensive dashboard")
    viz.create_dashboard()

    plt.show()
    print("\nVisualization complete. Close plots to continue.")

    return model, viz


def example_3_policy_comparison():
    """Example 3: Compare different policy configurations"""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: Policy Comparison")
    print("=" * 70)

    scenarios = [
        ("Baseline", {}),
        ("Aggressive Prompting", {
            'prompt_rate_natural': 0.3,
            'consent_rate_prompted': 0.6
        }),
        ("Strict Validation", {
            'transform_success_rate': 0.7,
            'git_merge_rate': 0.6
        }),
        ("Permissive", {
            'transform_success_rate': 0.98,
            'git_merge_rate': 0.95,
            'consent_rate_prompted': 0.7
        })
    ]

    results = []

    for name, params in scenarios:
        policy = PolicyParams(**params)
        model = FlywheelABM(n_users=100, policy=policy, seed=42)
        model.run(50)

        stats = model.get_summary_stats()
        results.append({
            'name': name,
            'total': stats['total_interactions'],
            'published': stats['stage_counts']['published_git'],
            'conversion': stats['stage_counts']['published_git'] / stats['total_interactions']
        })

    print("\nScenario Comparison:")
    print(f"{'Scenario':20s} {'Total':>10s} {'Published':>10s} {'Conv %':>10s}")
    print("-" * 55)
    for r in results:
        print(f"{r['name']:20s} {r['total']:10,} {r['published']:10,} {r['conversion']*100:9.2f}%")

    # Visualize comparison
    fig, ax = plt.subplots(figsize=(10, 6))
    names = [r['name'] for r in results]
    published = [r['published'] for r in results]

    bars = ax.bar(names, published, color='steelblue', alpha=0.7, edgecolor='black')

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height):,}', ha='center', va='bottom', fontweight='bold')

    ax.set_ylabel('Publications (Git)', fontsize=12)
    ax.set_title('Policy Impact on Publication Throughput', fontsize=14, fontweight='bold')
    ax.grid(axis='y', alpha=0.3)
    plt.xticks(rotation=15, ha='right')
    plt.tight_layout()
    plt.show()

    return results


def example_4_user_analysis():
    """Example 4: Analyze user contribution patterns"""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: User Contribution Analysis")
    print("=" * 70)

    model = FlywheelABM(n_users=200, seed=44)
    model.run(50)

    users = model.users

    # Sort by contributions
    sorted_users = sorted(users, key=lambda u: u.contributions_published, reverse=True)

    print("\nTop 10 Contributors:")
    print(f"{'Rank':>5s} {'User':15s} {'Published':>10s} {'Consent':>10s} {'Quality':>10s}")
    print("-" * 60)
    for i, user in enumerate(sorted_users[:10], 1):
        print(f"{i:5d} {user.username:15s} {user.contributions_published:10d} "
              f"{user.consent_propensity:10.3f} {user.quality_level:10.3f}")

    # Analyze contribution distribution
    contributions = [u.contributions_published for u in users]
    print(f"\nContribution Distribution:")
    print(f"  Total users: {len(users)}")
    print(f"  Users with contributions: {sum(1 for c in contributions if c > 0)}")
    print(f"  Mean contributions: {np.mean(contributions):.2f}")
    print(f"  Median contributions: {np.median(contributions):.2f}")
    print(f"  Max contributions: {np.max(contributions)}")

    # Gini coefficient (inequality measure)
    sorted_contrib = np.sort(contributions)
    n = len(sorted_contrib)
    cumsum = np.cumsum(sorted_contrib)
    gini = (2 * np.sum((np.arange(1, n+1)) * sorted_contrib)) / (n * np.sum(sorted_contrib)) - (n + 1) / n
    print(f"  Gini coefficient: {gini:.3f} (0=equal, 1=unequal)")

    # Scatter plot: consent vs quality, sized by contributions
    fig, ax = plt.subplots(figsize=(10, 6))

    consent = [u.consent_propensity for u in users]
    quality = [u.quality_level for u in users]
    sizes = [u.contributions_published * 10 + 10 for u in users]

    scatter = ax.scatter(consent, quality, s=sizes, alpha=0.5, c=contributions,
                        cmap='viridis', edgecolors='black', linewidth=0.5)

    ax.set_xlabel('Consent Propensity', fontsize=12)
    ax.set_ylabel('Quality Level', fontsize=12)
    ax.set_title('User Characteristics vs Contributions', fontsize=14, fontweight='bold')
    ax.grid(alpha=0.3)

    cbar = plt.colorbar(scatter, ax=ax)
    cbar.set_label('Published Contributions', fontsize=10)

    plt.tight_layout()
    plt.show()

    return model


def example_5_bottleneck_analysis():
    """Example 5: Identify pipeline bottlenecks"""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Bottleneck Analysis")
    print("=" * 70)

    model = FlywheelABM(n_users=100, seed=45)
    model.run(50)

    # Compute stage-wise conversion rates
    interactions = model.interactions

    total = len(interactions)
    eligible = sum(1 for i in interactions if i.E_i)
    captured = sum(1 for i in interactions if i.C_i)
    authorized = sum(1 for i in interactions if i.A_i)
    transformed = sum(1 for i in interactions if i.T_i)
    published = sum(1 for i in interactions if i.P_git)

    stages = [
        ("Total → Eligible", total, eligible),
        ("Eligible → Captured", eligible, captured),
        ("Captured → Authorized", captured, authorized),
        ("Authorized → Transformed", authorized, transformed),
        ("Transformed → Published", transformed, published)
    ]

    print("\nStage-wise Conversion Rates:")
    print(f"{'Stage':35s} {'From':>8s} {'To':>8s} {'Rate':>10s}")
    print("-" * 65)

    bottleneck_stage = None
    min_rate = 1.0

    for stage_name, from_count, to_count in stages:
        rate = to_count / from_count if from_count > 0 else 0
        print(f"{stage_name:35s} {from_count:8,} {to_count:8,} {rate*100:9.2f}%")

        if rate < min_rate:
            min_rate = rate
            bottleneck_stage = stage_name

    print(f"\nIdentified Bottleneck: {bottleneck_stage} ({min_rate*100:.2f}%)")

    # Recommendations
    print("\nRecommendations:")
    if "Authorized" in bottleneck_stage:
        print("  - Increase prompt_rate to surface more consent opportunities")
        print("  - Improve consent UX to raise consent_rate_prompted")
        print("  - Consider incentives for high-quality contributors")
    elif "Transformed" in bottleneck_stage:
        print("  - Review PII detection rules (may be too strict)")
        print("  - Provide contributors with validation feedback")
        print("  - Invest in better sanitization tooling")
    elif "Published" in bottleneck_stage:
        print("  - Streamline review/merge process")
        print("  - Add automated checks to reduce manual review burden")
        print("  - Consider tiered review (auto-merge for trusted users)")

    return model


def example_6_time_series_analysis():
    """Example 6: Analyze temporal dynamics"""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: Time Series Analysis")
    print("=" * 70)

    model = FlywheelABM(n_users=100, seed=46)
    model.run(100)  # Longer run

    metrics = model.metrics_history

    # Compute per-step throughput
    timesteps = metrics['timestep']
    throughput_git = np.diff([0] + metrics['published_git'])

    # Moving average
    window = 10
    if len(throughput_git) > window:
        moving_avg = np.convolve(throughput_git, np.ones(window)/window, mode='valid')

        print(f"\nThroughput Statistics (per timestep):")
        print(f"  Mean: {np.mean(throughput_git):.2f} publications/step")
        print(f"  Std dev: {np.std(throughput_git):.2f}")
        print(f"  Min: {np.min(throughput_git)}")
        print(f"  Max: {np.max(throughput_git)}")

        # Plot
        fig, ax = plt.subplots(figsize=(12, 6))

        ax.plot(timesteps, throughput_git, alpha=0.3, label='Raw throughput')
        ax.plot(timesteps[window-1:], moving_avg, linewidth=2,
               label=f'{window}-step moving average')

        ax.set_xlabel('Timestep', fontsize=12)
        ax.set_ylabel('Publications per Timestep', fontsize=12)
        ax.set_title('Flywheel Throughput Over Time', fontsize=14, fontweight='bold')
        ax.legend()
        ax.grid(alpha=0.3)

        plt.tight_layout()
        plt.show()

    return model


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("PUBLIC AI DATA FLYWHEEL - ABM EXAMPLES")
    print("=" * 70)

    # Run all examples
    model1 = example_1_basic_simulation()

    example_2_visualizations()

    results = example_3_policy_comparison()

    model4 = example_4_user_analysis()

    model5 = example_5_bottleneck_analysis()

    model6 = example_6_time_series_analysis()

    print("\n" + "=" * 70)
    print("All examples completed!")
    print("=" * 70)
