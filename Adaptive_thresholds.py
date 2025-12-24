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
for bars in [bars1, bars2]:
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}%',
                ha='center', va='bottom', fontsize=9, fontweight='bold')

# Left Y-axis styling
ax1.set_xlabel('Medical Risk Level', fontsize=13, fontweight='bold')
ax1.set_ylabel('False Positive Rate (%)', fontsize=13, fontweight='bold', color='tab:blue')
ax1.set_ylim(0, max(max(fpr_standard), max(fpr_adaptive)) * 1.35)
ax1.tick_params(axis='y', labelcolor='tab:blue', labelsize=11)
ax1.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.8)

# ============================================================================
# RIGHT Y-AXIS: Recall (Lines with Markers)
# ============================================================================
ax2 = ax1.twinx()

# Plot recall lines
line1 = ax2.plot(x, recall_standard, 'o-', 
                color='green', linewidth=2.5, markersize=10, 
                markeredgecolor='darkgreen', markeredgewidth=2,
                label='Recall - Standard Threshold', alpha=0.9, zorder=5)
line2 = ax2.plot(x, recall_adaptive, 's--', 
                color='red', linewidth=2.5, markersize=9, 
                markeredgecolor='darkred', markeredgewidth=2,
                label='Recall - Adaptive Threshold', alpha=0.9, zorder=5)

# Add value labels on line markers
for i, (std, adp) in enumerate(zip(recall_standard, recall_adaptive)):
    # Standard recall (green)
    ax2.text(i, std + 3, f'{std:.0f}%', 
            ha='center', va='bottom', fontsize=10, 
            fontweight='bold', color='darkgreen')
    # Adaptive recall (red)
    ax2.text(i, adp - 3, f'{adp:.0f}%', 
            ha='center', va='top', fontsize=10, 
            fontweight='bold', color='darkred')

# Right Y-axis styling
ax2.set_ylabel('Recall (%)', fontsize=13, fontweight='bold', color='darkred')
ax2.set_ylim(0, 110)
ax2.tick_params(axis='y', labelcolor='darkred', labelsize=11)

# ============================================================================
# Annotations
# ============================================================================
# L3 Success: FPR reduction
if fpr_change[2] < 0:
    improvement_pct = abs(fpr_change[2]) / fpr_standard[2] * 100
    ax1.annotate(f'↓{improvement_pct:.0f}% FPR', 
                xy=(2 + width/2, fpr_adaptive[2]),
                xytext=(2 + width/2 + 0.35, fpr_adaptive[2] + 6),
                fontsize=11, fontweight='bold', color='green',
                arrowprops=dict(arrowstyle='->', color='green', lw=2.5),
                bbox=dict(boxstyle='round,pad=0.4', facecolor='lightgreen', 
                        edgecolor='green', alpha=0.8))

# ============================================================================
# Styling and Layout
# ============================================================================
ax1.set_title('Adaptive Threshold Effectiveness: FPR vs Recall Trade-off\nAcross Medical Risk Levels',
            fontsize=14, fontweight='bold', pad=20)
ax1.set_xticks(x)
ax1.set_xticklabels(risk_labels, fontsize=11)
ax1.spines['top'].set_visible(False)

# Combine legends from both axes
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, 
        loc='upper right', fontsize=10, framealpha=0.95,
        title='Metrics', title_fontsize=11)

plt.tight_layout()

# Save outputs
jpg_file = OUTPUT_DIR / 'adaptive_thresholds.jpg'
plt.savefig(jpg_file, dpi=300, bbox_inches='tight')

print(f"\n✅ Saved JPG: {jpg_file}")

# ==============================================================================
# Console Output
# ==============================================================================
print("\n" + "="*70)
print("KEY FINDINGS (DUAL-AXIS ANALYSIS)")
print("="*70)

# Highlight L3 success
l3_improvement = abs(fpr_change[2]) / fpr_standard[2] * 100
print(f"⭐ L3 (High Risk): FPR reduced by {l3_improvement:.1f}% (33.33% → 16.67%)")
print(f"   Recall unchanged: {recall_standard[2]:.0f}% → {recall_adaptive[2]:.0f}%")
print(f"   ✅ OPTIMAL TRADE-OFF: Lower FPR without sacrificing detection")

# Explain L1/L2 no change
if fpr_change[0] == 0 and fpr_change[1] == 0:
    print(f"\n✓ L1/L2 (Critical/Severe): No FPR change")
    print(f"   L1 Recall: {recall_standard[0]:.0f}% → {recall_adaptive[0]:.0f}% (Perfect detection)")
    print(f"   L2 Recall: {recall_standard[1]:.0f}% → {recall_adaptive[1]:.0f}%")
    print(f"   Reason: High-confidence cases already correctly classified")


# Visualize trade-off
print("\n" + "="*70)
print("TRADE-OFF MATRIX")
print("="*70)
print("Level | FPR Change | Recall Change | Assessment")
print("------|------------|---------------|------------")
for i, level in enumerate(risk_levels):
    fpr_arrow = "⬇️" if fpr_change[i] < 0 else "➡️" if fpr_change[i] == 0 else "⬆️"
    recall_arrow = "⬇️" if recall_change[i] < 0 else "➡️" if recall_change[i] == 0 else "⬆️"
    
    if fpr_change[i] < 0 and recall_change[i] >= 0:
        assessment = "✅ SUCCESS"
    elif fpr_change[i] == 0 and recall_change[i] >= 0:
        assessment = "✓ STABLE"
    elif recall_change[i] < -30:
        assessment = "❌ FAILURE"
    else:
        assessment = "⚠ REVIEW"
    
    print(f"{level:5} | {fpr_arrow:2} {fpr_change[i]:+6.1f}% | {recall_arrow:2} {recall_change[i]:+6.0f}%  | {assessment}")

print("\n" + "="*70)
print("DUAL-AXIS VISUALIZATION COMPLETE")
print("="*70)
print("The chart now shows:")
print("  📊 LEFT AXIS (Blue): False Positive Rate (bars)")
print("  📈 RIGHT AXIS (Red): Recall (lines)")
print("  ➡️ Enables direct visual comparison of FPR-Recall trade-offs")
print("="*70)
