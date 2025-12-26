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
COLOR_RULE1 = '#B3D9FF'  # Light blue
COLOR_RULE2 = '#D1B3FF'  # Light purple (will have red border)
COLOR_RULE3 = '#FFB3D9'  # Light pink

# ==============================================================================
# Load and Process Data
# ==============================================================================
print("="*70)
print("ABLATION STUDY ANALYSIS")
print("="*70)

df = pd.read_csv(INPUT_CSV)

# Extract rule names and F1 drops
rule_names = ['Rule 1\n(Consistency)', 'Rule 2\n(Strong Evidence)', 'Rule 3\n(Medical Risk)']
f1_drops = []
colors = [COLOR_RULE1, COLOR_RULE2, COLOR_RULE3]
edge_colors = ['black', 'red', 'black']  # Red border for Rule 2
edge_widths = [1.5, 3.5, 1.5]  # Thicker border for Rule 2

for idx, row in df.iterrows():
    rule_name = row.iloc[0]
    if 'Without Rule 1' in rule_name:
        f1_drops.append(row['F1_drop'])
    elif 'Without Rule 2' in rule_name:
        f1_drops.append(row['F1_drop'])
    elif 'Without Rule 3' in rule_name:
        f1_drops.append(row['F1_drop'])

# ==============================================================================
# Create Vertical Bar Chart (Summary.png Style)
# ==============================================================================
fig, ax = plt.subplots(figsize=(8, 6))

x_pos = np.arange(len(rule_names))
bars = ax.bar(x_pos, f1_drops, color=colors, 
               edgecolor=edge_colors, linewidth=edge_widths,
               width=0.6, alpha=0.85)

# Add value labels on top of bars
for i, (bar, value) in enumerate(zip(bars, f1_drops)):
    ax.text(bar.get_x() + bar.get_width()/2, value + 0.15,
            f'+{value:.2f}%',
            ha='center', va='bottom', fontsize=13, fontweight='bold',
            color='black')

# Styling - matching Summary.png
ax.set_ylabel('F1-Score Drop (%)', fontsize=13, fontweight='bold')
ax.set_title('RQ4: Ablation Study\nAll Rules Positive Contribution',
             fontsize=14, fontweight='bold', pad=15)
ax.set_xticks(x_pos)
ax.set_xticklabels(rule_names, fontsize=12, fontweight='bold')
ax.set_ylim(0, max(f1_drops) * 1.25)

# Grid styling
ax.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.8, zorder=0)
ax.set_axisbelow(True)

# Spine styling
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_linewidth(1.5)
ax.spines['bottom'].set_linewidth(1.5)

# Add subtle background color
ax.set_facecolor('#F8F8F8')
fig.patch.set_facecolor('white')

plt.tight_layout()

# Save outputs
jpg_file = OUTPUT_DIR / 'ablation_study.jpg'
plt.savefig(jpg_file, dpi=300, bbox_inches='tight')

print(f"\n✅ Saved JPG: {jpg_file}")
