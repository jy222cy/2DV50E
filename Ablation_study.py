import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# ==============================================================================
# Configuration
# ==============================================================================
INPUT_CSV = Path("C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_4/ablation_study.csv")
OUTPUT_DIR = Path("C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_4/")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Journal-standard colors
COLOR_SIGNIFICANT = '#d62728'  # Red for significant impact
COLOR_MODERATE = '#ff7f0e'     # Orange for moderate impact
COLOR_NONE = '#1f77b4'         # Blue for no impact

# ==============================================================================
# Load and Process Data
# ==============================================================================
print("="*70)
print("ABLATION STUDY ANALYSIS")
print("="*70)

df = pd.read_csv(INPUT_CSV)

# Extract rule names and F1 drops
rules = []
f1_drops = []
colors = []

for idx, row in df.iterrows():
    rule_name = row.iloc[0]
    if 'Baseline' in rule_name:
        continue  # Skip baseline
    
    # Extract rule number and name
    if 'Without Rule 1' in rule_name:
        rules.append('Rule 1\nConsistency Reward')
        f1_drops.append(row['F1_drop'])
        colors.append(COLOR_MODERATE if row['F1_drop'] > 0 else COLOR_NONE)
    elif 'Without Rule 2' in rule_name:
        rules.append('Rule 2\nDivergence Penalty')
        f1_drops.append(row['F1_drop'])
        colors.append(COLOR_NONE)
    elif 'Without Rule 3' in rule_name:
        rules.append('Rule 3\nStrong Evidence Boost')
        f1_drops.append(row['F1_drop'])
        colors.append(COLOR_SIGNIFICANT)
    elif 'Without Rule 4' in rule_name:
        rules.append('Rule 4\nMedical Field Bonus')
        f1_drops.append(row['F1_drop'])
        colors.append(COLOR_NONE)

# ==============================================================================
# Create Horizontal Bar Chart
# ==============================================================================
fig, ax = plt.subplots(figsize=(10, 6))

y_pos = np.arange(len(rules))
bars = ax.barh(y_pos, f1_drops, color=colors, edgecolor='black', linewidth=1.2)

# Add value labels
for i, (bar, value) in enumerate(zip(bars, f1_drops)):
    if value > 0:
        ax.text(value + 0.5, bar.get_y() + bar.get_height()/2, 
                f'{value:.2f}%',
                ha='left', va='center', fontsize=11, fontweight='bold')
    else:
        # Special annotation for zero-impact rules
        ax.text(0.5, bar.get_y() + bar.get_height()/2,
                'No Impact',
                ha='left', va='center', fontsize=10, 
                style='italic', color='gray')

# Highlight Rule 3 with special marker
max_idx = f1_drops.index(max(f1_drops))
ax.plot(f1_drops[max_idx], max_idx, 'r*', markersize=20, 
        label='Critical Component', zorder=10)

# Styling
ax.set_xlabel('F1-Score Drop When Rule Removed (%)', fontsize=12, fontweight='bold')
ax.set_ylabel('Heuristic Rule', fontsize=12, fontweight='bold')
ax.set_title('Ablation Study: Individual Heuristic Rule Contributions\nPerformance Degradation When Components Removed',
            fontsize=14, fontweight='bold', pad=20)
ax.set_yticks(y_pos)
ax.set_yticklabels(rules, fontsize=11)
ax.set_xlim(0, max(f1_drops) * 1.2)
ax.grid(axis='x', alpha=0.3, linestyle='--')
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

# Add legend
legend_elements = [
    plt.Rectangle((0,0),1,1, fc=COLOR_SIGNIFICANT, ec='black', label='Critical Impact (>15%)'),
    plt.Rectangle((0,0),1,1, fc=COLOR_MODERATE, ec='black', label='Moderate Impact (3-15%)'),
    plt.Rectangle((0,0),1,1, fc=COLOR_NONE, ec='black', label='No Impact (<3%)')
]
ax.legend(handles=legend_elements, loc='lower right', fontsize=10, framealpha=0.9)

plt.tight_layout()

# Save outputs
jpg_file = OUTPUT_DIR / 'ablation_study.jpg'
plt.savefig(jpg_file, dpi=300, bbox_inches='tight')

print(f"\n✅ Saved JPG: {jpg_file}")


# ==============================================================================
# Generate Summary Statistics
# ==============================================================================
summary_data = {
    'Rule': rules,
    'F1_Drop(%)': [f"{x:.2f}" for x in f1_drops],
    'Impact_Category': [
        'Critical (>15%)' if x > 15 else 
        'Moderate (3-15%)' if x >= 3 else 
        'None (<3%)'
        for x in f1_drops
    ],
    'Interpretation': [
        'Essential component - largest performance contributor',
        'Minimal impact - improves consistency in edge cases',
        'No observable effect - may indicate threshold issues',
        'No observable effect - medical scenarios underrepresented'
    ]
}

summary_df = pd.DataFrame(summary_data)
summary_csv = OUTPUT_DIR / 'ablation_study_summary.csv'
summary_df.to_csv(summary_csv, index=False)
print(f"✅ Saved Summary: {summary_csv}")

# ==============================================================================
# Console Output
# ==============================================================================
print("\n" + "="*70)
print("ABLATION STUDY RESULTS")
print("="*70)
print(summary_df.to_string(index=False))

print("\n" + "="*70)
print("KEY FINDINGS")
print("="*70)

# Critical component
max_drop = max(f1_drops)
max_rule = rules[f1_drops.index(max_drop)]
print(f"🔴 {max_rule.replace(chr(10), ' ')}: {max_drop:.2f}% drop")
print(f"   → CRITICAL component: Without strong evidence detection,")
print(f"     system cannot distinguish high-confidence SQL errors from ambiguous signals")
print(f"   → This rule enforces minimum 0.80 confidence when SQL errors detected")

# Moderate component
moderate_drops = [(r, d) for r, d in zip(rules, f1_drops) if 3 <= d < 15]
if moderate_drops:
    for rule, drop in moderate_drops:
        print(f"\n🟠 {rule.replace(chr(10), ' ')}: {drop:.2f}% drop")
        print(f"   → Moderate impact: Helps in borderline cases near 0.50 threshold")

# Zero-impact components
zero_drops = [(r, d) for r, d in zip(rules, f1_drops) if d < 3]
if zero_drops:
    print(f"\n🔵 Zero-Impact Rules:")
    for rule, drop in zero_drops:
        print(f"   • {rule.replace(chr(10), ' ')}: {drop:.2f}% drop")
    print(f"   → Possible reasons:")
    print(f"     (1) Test cases lack scenarios where these rules trigger")
    print(f"     (2) Other rules already capture similar patterns")
    print(f"     (3) Parameters need recalibration based on this finding")

print("\n" + "="*70)
print("VISUALIZATION COMPLETE")
print("="*70)