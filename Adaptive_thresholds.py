import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# ==============================================================================
# Configuration
# ==============================================================================
INPUT_CSV = Path("C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_3/adaptive_thresholds_test.csv")
OUTPUT_DIR = Path("C:/Users/jiani/Desktop/Degree Project/2DV50E/outputs/Experiment_3/")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Journal-standard colors
COLOR_STANDARD = '#1f77b4'  # Blue
COLOR_ADAPTIVE = '#ff7f0e'  # Orange

# ==============================================================================
# Load and Process Data
# ==============================================================================
print("="*70)
print("ADAPTIVE THRESHOLDS EFFECTIVENESS ANALYSIS (DUAL-AXIS)")
print("="*70)

df = pd.read_csv(INPUT_CSV)

# Extract FPR and Recall data for each risk level
risk_levels = ['L1', 'L2', 'L3', 'L4']
risk_labels = ['L1\n(Critical)', 'L2\n(Severe)', 'L3\n(High)', 'L4\n(Medium)']

fpr_standard = []
fpr_adaptive = []
recall_standard = []
recall_adaptive = []

for level in risk_levels:
    std_row = df[df.iloc[:, 0] == f'{level}_Standard'].iloc[0]
    adp_row = df[df.iloc[:, 0] == f'{level}_Adaptive'].iloc[0]
    
    fpr_standard.append(std_row['fpr'] * 100)  # Convert to percentage
    fpr_adaptive.append(adp_row['fpr'] * 100)
    recall_standard.append(std_row['recall'] * 100)
    recall_adaptive.append(adp_row['recall'] * 100)

# Calculate improvements
fpr_change = [adp - std for std, adp in zip(fpr_standard, fpr_adaptive)]
recall_change = [adp - std for std, adp in zip(recall_standard, recall_adaptive)]

# ==============================================================================
# Create Dual-Axis Chart: FPR (Bars) + Recall (Lines)
# ==============================================================================
fig, ax1 = plt.subplots(figsize=(12, 7))

x = np.arange(len(risk_levels))
width = 0.35

# ============================================================================
# LEFT Y-AXIS: False Positive Rate (Bars)
# ============================================================================
bars1 = ax1.bar(x - width/2, fpr_standard, width, 
            label='FPR - Standard Threshold (0.50)', 
            color=COLOR_STANDARD, edgecolor='black', linewidth=1.2, alpha=0.7)
bars2 = ax1.bar(x + width/2, fpr_adaptive, width,
            label='FPR - Adaptive Threshold',
            color=COLOR_ADAPTIVE, edgecolor='black', linewidth=1.2, alpha=0.7)

# Add value labels on bars
for idx, bars in enumerate([bars1, bars2]):
    for bar_idx, bar in enumerate(bars):
        height = bar.get_height()
        
        if bar_idx == 2 and idx == 0:
            ax1.text(bar.get_x() + bar.get_width()/2., height * 0.5,
                    f'{height:.1f}%',
                    ha='center', va='center', fontsize=10, fontweight='bold',
                    color='white', zorder=10,
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='navy', 
                            edgecolor='white', linewidth=1.5, alpha=0.9))
        else:
            ax1.text(bar.get_x() + bar.get_width()/2., height + 1.5,
                    f'{height:.1f}%',
                    ha='center', va='bottom', fontsize=10, fontweight='bold',
                    zorder=10)

# Left Y-axis styling
ax1.set_xlabel('Medical Risk Level', fontsize=14, fontweight='bold')
ax1.set_ylabel('False Positive Rate (%)', fontsize=14, fontweight='bold', color='tab:blue')
ax1.set_ylim(0, 65)
ax1.tick_params(axis='y', labelcolor='tab:blue', labelsize=12)
ax1.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.8)

# ============================================================================
# RIGHT Y-AXIS: Recall (Lines with Markers)
# ============================================================================
ax2 = ax1.twinx()

# Plot recall lines
line1 = ax2.plot(x, recall_standard, 'o-', 
                color='green', linewidth=2.5, markersize=10, 
                markeredgecolor='darkgreen', markeredgewidth=2,
                label='Recall - Standard Threshold', alpha=0.85, zorder=3)
line2 = ax2.plot(x, recall_adaptive, 's--', 
                color='red', linewidth=2.5, markersize=9, 
                markeredgecolor='darkred', markeredgewidth=2,
                label='Recall - Adaptive Threshold', alpha=0.85, zorder=3)

# Add value labels on line markers
for i, (std, adp) in enumerate(zip(recall_standard, recall_adaptive)):
    if i == 1:  # L2
        # Standard recall (green)
        ax2.text(i - 0.12, std - 4.5, f'{std:.1f}%', 
                ha='center', va='top', fontsize=10, 
                fontweight='bold', color='darkgreen', zorder=10,
                bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgreen', 
                        edgecolor='darkgreen', alpha=0.85))
        # Adaptive recall (red)
        ax2.text(i + 0.12, adp + 1.5, f'{adp:.1f}%', 
                ha='center', va='bottom', fontsize=10, 
                fontweight='bold', color='darkred', zorder=10,
                bbox=dict(boxstyle='round,pad=0.3', facecolor='lightcoral', 
                        edgecolor='darkred', alpha=0.85))
    else:
        # Standard recall (green)
        ax2.text(i, std + 3, f'{std:.1f}%', 
                ha='center', va='bottom', fontsize=10, 
                fontweight='bold', color='darkgreen', zorder=10)
        # Adaptive recall (red)
        ax2.text(i, adp - 3, f'{adp:.1f}%', 
                ha='center', va='top', fontsize=10, 
                fontweight='bold', color='darkred', zorder=10)

# Right Y-axis styling
ax2.set_ylabel('Recall (%)', fontsize=14, fontweight='bold', color='darkred')
ax2.set_ylim(0, 115)
ax2.tick_params(axis='y', labelcolor='darkred', labelsize=12)

# ============================================================================
# Annotations - L3 Success: FPR reduction
# ============================================================================
fpr_change = [adp - std for std, adp in zip(fpr_standard, fpr_adaptive)]
if fpr_change[2] < 0:
    fpr_std_rounded = round(fpr_standard[2], 1)
    fpr_adp_rounded = round(fpr_adaptive[2], 1)
    absolute_reduction = fpr_std_rounded - fpr_adp_rounded
    
    ax1.annotate(f'↓{absolute_reduction:.1f} FPR',
                xy=(2 + width/2, fpr_adaptive[2]),
                xytext=(2.5, 10),
                fontsize=11, fontweight='bold', color='green',
                arrowprops=dict(arrowstyle='->', color='green', lw=2.5),
                bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgreen', 
                        edgecolor='green', linewidth=2, alpha=0.9),
                zorder=10)

# ============================================================================
# Styling and Layout
# ============================================================================
ax1.set_title('Adaptive Threshold Effectiveness: FPR vs Recall Trade-off\nAcross Medical Risk Levels',
            fontsize=15, fontweight='bold', pad=20)
ax1.set_xticks(x)
ax1.set_xticklabels(risk_labels, fontsize=12, fontweight='bold')
ax1.spines['top'].set_visible(False)

# Combine legends from both axes
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, 
        loc='upper right', fontsize=11, framealpha=0.95,
        title='Metrics', title_fontsize=12, edgecolor='black', fancybox=True)

plt.tight_layout()

# Save outputs
jpg_file = OUTPUT_DIR / 'adaptive_thresholds.jpg'
plt.savefig(jpg_file, dpi=300, bbox_inches='tight')

print(f"\n✅ Saved JPG: {jpg_file}")
