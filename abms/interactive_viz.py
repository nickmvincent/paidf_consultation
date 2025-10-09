"""
Interactive Visualization for Public AI Data Flywheel ABM

Provides interactive controls and visualizations for exploring the flywheel dynamics.
Uses matplotlib for plotting and ipywidgets for interactive controls (Jupyter-compatible).
"""

import matplotlib.pyplot as plt
import numpy as np
from typing import Optional, Dict, List
from flywheel_abm import FlywheelABM, PolicyParams


class FlywheelViz:
    """Visualization and analysis tools for the flywheel ABM"""

    def __init__(self, model: FlywheelABM):
        self.model = model

    def plot_funnel(self, figsize=(10, 6)):
        """Plot the conversion funnel through pipeline stages"""
        fig, ax = plt.subplots(figsize=figsize)

        stats = self.model.get_summary_stats()
        stage_counts = stats['stage_counts']

        # Define stages and their counts
        stages = [
            ('Total\nInteractions', stats['total_interactions']),
            ('Eligible\n(E_i)', stage_counts['eligible']),
            ('Captured\n(C_i)', stage_counts['captured']),
            ('Authorized\n(A_i)', stage_counts['authorized']),
            ('Transformed\n(T_i)', stage_counts['transformed']),
            ('Published\nGit', stage_counts['published_git']),
        ]

        stage_names = [s[0] for s in stages]
        counts = [s[1] for s in stages]

        # Create funnel chart
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(stages)))

        bars = ax.barh(stage_names, counts, color=colors)

        # Add count labels
        for i, (bar, count) in enumerate(zip(bars, counts)):
            ax.text(count + max(counts) * 0.02, i, f'{count:,}',
                   va='center', fontweight='bold')

            # Add conversion rate from previous stage
            if i > 0:
                prev_count = counts[i - 1]
                rate = (count / prev_count * 100) if prev_count > 0 else 0
                ax.text(count / 2, i, f'{rate:.1f}%',
                       va='center', ha='center', color='white', fontweight='bold')

        ax.set_xlabel('Number of Interactions', fontsize=12)
        ax.set_title('Data Flywheel Conversion Funnel', fontsize=14, fontweight='bold')
        ax.grid(axis='x', alpha=0.3)

        plt.tight_layout()
        return fig

    def plot_time_series(self, figsize=(12, 8)):
        """Plot time series of key metrics"""
        fig, axes = plt.subplots(2, 2, figsize=figsize)

        metrics = self.model.metrics_history
        timesteps = metrics['timestep']

        # Plot 1: Cumulative interactions
        ax = axes[0, 0]
        ax.plot(timesteps, metrics['total_interactions'], label='Total', linewidth=2)
        ax.plot(timesteps, metrics['authorized'], label='Authorized', linewidth=2)
        ax.plot(timesteps, metrics['published_git'], label='Published (Git)', linewidth=2)
        ax.set_xlabel('Timestep')
        ax.set_ylabel('Cumulative Count')
        ax.set_title('Cumulative Interactions Over Time')
        ax.legend()
        ax.grid(alpha=0.3)

        # Plot 2: Stage rates
        ax = axes[0, 1]
        if len(timesteps) > 0:
            ax.plot(timesteps, metrics['p_c'], label='p_c (capture)', linewidth=2)
            ax.plot(timesteps, metrics['p_a'], label='p_a (consent)', linewidth=2)
            ax.plot(timesteps, metrics['p_t'], label='p_t (transform)', linewidth=2)
            ax.plot(timesteps, metrics['p_k_git'], label='p_k (git merge)', linewidth=2)
        ax.set_xlabel('Timestep')
        ax.set_ylabel('Rate')
        ax.set_title('Stage-Specific Rates')
        ax.legend()
        ax.grid(alpha=0.3)
        ax.set_ylim([0, 1.1])

        # Plot 3: Publications by channel
        ax = axes[1, 0]
        ax.plot(timesteps, metrics['published_git'], label='Git', linewidth=2)
        ax.plot(timesteps, metrics['published_hf'], label='HuggingFace', linewidth=2)
        ax.plot(timesteps, metrics['published_bsky'], label='Bluesky', linewidth=2)
        ax.set_xlabel('Timestep')
        ax.set_ylabel('Cumulative Publications')
        ax.set_title('Publications by Channel')
        ax.legend()
        ax.grid(alpha=0.3)

        # Plot 4: Per-timestep throughput
        ax = axes[1, 1]
        if len(timesteps) > 1:
            throughput_git = np.diff([0] + metrics['published_git'])
            throughput_hf = np.diff([0] + metrics['published_hf'])

            ax.plot(timesteps, throughput_git, label='Git (per step)', alpha=0.7)
            ax.plot(timesteps, throughput_hf, label='HF (per step)', alpha=0.7)

            # Add smoothed trend
            if len(throughput_git) > 5:
                window = 5
                smooth_git = np.convolve(throughput_git, np.ones(window)/window, mode='valid')
                ax.plot(timesteps[window-1:], smooth_git, label='Git (smoothed)',
                       linewidth=2, linestyle='--')

        ax.set_xlabel('Timestep')
        ax.set_ylabel('Publications per Step')
        ax.set_title('Publication Throughput (Λ_k)')
        ax.legend()
        ax.grid(alpha=0.3)

        plt.tight_layout()
        return fig

    def plot_user_distributions(self, figsize=(12, 5)):
        """Plot distributions of user characteristics"""
        fig, axes = plt.subplots(1, 3, figsize=figsize)

        users = self.model.users

        # Consent propensity
        ax = axes[0]
        consent_props = [u.consent_propensity for u in users]
        ax.hist(consent_props, bins=20, alpha=0.7, color='steelblue', edgecolor='black')
        ax.axvline(np.mean(consent_props), color='red', linestyle='--',
                   label=f'Mean: {np.mean(consent_props):.2f}')
        ax.set_xlabel('Consent Propensity')
        ax.set_ylabel('Number of Users')
        ax.set_title('Distribution of Consent Propensity')
        ax.legend()
        ax.grid(alpha=0.3)

        # Quality level
        ax = axes[1]
        quality_levels = [u.quality_level for u in users]
        ax.hist(quality_levels, bins=20, alpha=0.7, color='forestgreen', edgecolor='black')
        ax.axvline(np.mean(quality_levels), color='red', linestyle='--',
                   label=f'Mean: {np.mean(quality_levels):.2f}')
        ax.set_xlabel('Quality Level')
        ax.set_ylabel('Number of Users')
        ax.set_title('Distribution of Quality Level')
        ax.legend()
        ax.grid(alpha=0.3)

        # Activity rate
        ax = axes[2]
        activity_rates = [u.activity_rate for u in users]
        ax.hist(activity_rates, bins=20, alpha=0.7, color='coral', edgecolor='black')
        ax.axvline(np.mean(activity_rates), color='red', linestyle='--',
                   label=f'Mean: {np.mean(activity_rates):.2f}')
        ax.set_xlabel('Activity Rate (interactions/step)')
        ax.set_ylabel('Number of Users')
        ax.set_title('Distribution of Activity Rate')
        ax.legend()
        ax.grid(alpha=0.3)

        plt.tight_layout()
        return fig

    def plot_license_breakdown(self, figsize=(8, 6)):
        """Plot breakdown of licenses and attribution types in published contributions"""
        fig, axes = plt.subplots(1, 2, figsize=figsize)

        published = [i for i in self.model.interactions if i.P_git and i.metadata]

        if not published:
            print("No published contributions yet.")
            return None

        # License breakdown
        ax = axes[0]
        licenses = [i.metadata.license.value for i in published]
        license_counts = {}
        for lic in licenses:
            license_counts[lic] = license_counts.get(lic, 0) + 1

        ax.pie(license_counts.values(), labels=license_counts.keys(),
               autopct='%1.1f%%', startangle=90)
        ax.set_title('License Distribution\n(Published Contributions)')

        # Attribution breakdown
        ax = axes[1]
        attributions = [i.metadata.attribution.value for i in published]
        attr_counts = {}
        for attr in attributions:
            attr_counts[attr] = attr_counts.get(attr, 0) + 1

        ax.pie(attr_counts.values(), labels=attr_counts.keys(),
               autopct='%1.1f%%', startangle=90)
        ax.set_title('Attribution Type Distribution\n(Published Contributions)')

        plt.tight_layout()
        return fig

    def create_dashboard(self, figsize=(16, 12)):
        """Create a comprehensive dashboard"""
        fig = plt.figure(figsize=figsize)

        # Create grid
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)

        # Time series (top row, full width)
        ax1 = fig.add_subplot(gs[0, :])
        metrics = self.model.metrics_history
        timesteps = metrics['timestep']
        ax1.plot(timesteps, metrics['total_interactions'], label='Total', linewidth=2)
        ax1.plot(timesteps, metrics['captured'], label='Captured', linewidth=2)
        ax1.plot(timesteps, metrics['authorized'], label='Authorized', linewidth=2)
        ax1.plot(timesteps, metrics['published_git'], label='Published', linewidth=2)
        ax1.set_xlabel('Timestep')
        ax1.set_ylabel('Cumulative Count')
        ax1.set_title('Flywheel Pipeline: Cumulative Interactions', fontweight='bold')
        ax1.legend(loc='upper left')
        ax1.grid(alpha=0.3)

        # Funnel (middle left)
        ax2 = fig.add_subplot(gs[1, 0])
        stats = self.model.get_summary_stats()
        stage_counts = stats['stage_counts']
        stages = ['Total', 'Eligible', 'Captured', 'Auth', 'Trans', 'Pub']
        counts = [
            stats['total_interactions'],
            stage_counts['eligible'],
            stage_counts['captured'],
            stage_counts['authorized'],
            stage_counts['transformed'],
            stage_counts['published_git']
        ]
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(stages)))
        bars = ax2.barh(stages, counts, color=colors)
        for bar, count in zip(bars, counts):
            ax2.text(count + max(counts) * 0.02, bar.get_y() + bar.get_height()/2,
                    f'{count:,}', va='center', fontsize=8)
        ax2.set_xlabel('Count')
        ax2.set_title('Conversion Funnel', fontweight='bold')
        ax2.grid(axis='x', alpha=0.3)

        # Stage rates (middle center)
        ax3 = fig.add_subplot(gs[1, 1])
        if len(timesteps) > 0:
            ax3.plot(timesteps, metrics['p_c'], label='p_c', linewidth=2)
            ax3.plot(timesteps, metrics['p_a'], label='p_a', linewidth=2)
            ax3.plot(timesteps, metrics['p_t'], label='p_t', linewidth=2)
            ax3.plot(timesteps, metrics['p_k_git'], label='p_k', linewidth=2)
        ax3.set_xlabel('Timestep')
        ax3.set_ylabel('Rate')
        ax3.set_title('Stage Rates', fontweight='bold')
        ax3.legend()
        ax3.grid(alpha=0.3)
        ax3.set_ylim([0, 1.1])

        # User characteristics (middle right)
        ax4 = fig.add_subplot(gs[1, 2])
        users = self.model.users
        consent_props = [u.consent_propensity for u in users]
        quality_levels = [u.quality_level for u in users]
        ax4.scatter(consent_props, quality_levels, alpha=0.5, s=30)
        ax4.set_xlabel('Consent Propensity')
        ax4.set_ylabel('Quality Level')
        ax4.set_title('User Characteristics', fontweight='bold')
        ax4.grid(alpha=0.3)

        # License pie (bottom left)
        ax5 = fig.add_subplot(gs[2, 0])
        published = [i for i in self.model.interactions if i.P_git and i.metadata]
        if published:
            licenses = [i.metadata.license.value for i in published]
            license_counts = {}
            for lic in licenses:
                license_counts[lic] = license_counts.get(lic, 0) + 1
            ax5.pie(license_counts.values(), labels=license_counts.keys(),
                   autopct='%1.1f%%', startangle=90)
            ax5.set_title('Licenses', fontweight='bold')

        # Attribution pie (bottom center)
        ax6 = fig.add_subplot(gs[2, 1])
        if published:
            attributions = [i.metadata.attribution.value for i in published]
            attr_counts = {}
            for attr in attributions:
                attr_counts[attr] = attr_counts.get(attr, 0) + 1
            ax6.pie(attr_counts.values(), labels=attr_counts.keys(),
                   autopct='%1.1f%%', startangle=90)
            ax6.set_title('Attribution', fontweight='bold')

        # Summary stats (bottom right)
        ax7 = fig.add_subplot(gs[2, 2])
        ax7.axis('off')
        summary_text = f"""
        SUMMARY STATISTICS
        {'='*25}

        Timestep: {stats['timestep']}
        Users: {stats['n_users']}

        Total Interactions: {stats['total_interactions']:,}
        Published (Git): {stage_counts['published_git']:,}

        Conversion Rate:
          {(stage_counts['published_git']/stats['total_interactions']*100 if stats['total_interactions'] > 0 else 0):.2f}%

        Avg Consent: {stats['user_stats']['avg_consent_propensity']:.2f}
        Avg Quality: {stats['user_stats']['avg_quality_level']:.2f}
        """
        ax7.text(0.1, 0.5, summary_text, fontsize=10, family='monospace',
                verticalalignment='center')

        fig.suptitle('Public AI Data Flywheel - Dashboard', fontsize=16, fontweight='bold')

        return fig


def run_interactive_scenario(policy_params: Dict = None, n_users: int = 100,
                             n_steps: int = 50, seed: int = 42):
    """Run a scenario with custom parameters and visualize results"""

    # Create policy from params if provided
    policy = PolicyParams(**policy_params) if policy_params else PolicyParams()

    # Initialize and run model
    model = FlywheelABM(n_users=n_users, policy=policy, seed=seed)
    model.run(n_steps)

    # Create visualizations
    viz = FlywheelViz(model)

    # Generate plots
    print(f"\nScenario Results (n_users={n_users}, n_steps={n_steps})")
    print("=" * 60)

    stats = model.get_summary_stats()
    print(f"Total Interactions: {stats['total_interactions']:,}")
    print(f"Published to Git: {stats['stage_counts']['published_git']:,}")
    print(f"Overall Conversion: {(stats['stage_counts']['published_git']/stats['total_interactions']*100 if stats['total_interactions'] > 0 else 0):.2f}%")

    # Show dashboard
    viz.create_dashboard()
    plt.show()

    return model, viz


if __name__ == "__main__":
    import json

    print("Interactive Flywheel Visualization")
    print("=" * 60)

    # Scenario 1: Baseline
    print("\n### Scenario 1: Baseline Parameters ###")
    model1, viz1 = run_interactive_scenario(n_users=100, n_steps=50, seed=42)

    # Scenario 2: High consent, low quality
    print("\n### Scenario 2: Aggressive Prompting (higher q_i) ###")
    model2, viz2 = run_interactive_scenario(
        policy_params={
            'prompt_rate_natural': 0.3,  # More prompting
            'prompt_rate_prompted': 0.9,
            'consent_rate_prompted': 0.6,  # Higher consent when prompted
        },
        n_users=100,
        n_steps=50,
        seed=43
    )

    # Scenario 3: Stricter validation
    print("\n### Scenario 3: Stricter Validation (lower p_t) ###")
    model3, viz3 = run_interactive_scenario(
        policy_params={
            'transform_success_rate': 0.7,  # Stricter PII checks
            'git_merge_rate': 0.6,  # Stricter review
        },
        n_users=100,
        n_steps=50,
        seed=44
    )
