# Deobfuscation Presets Guide

## Overview

Veriscope's preset system eliminates the need for manual threshold tuning when analyzing different types of obfuscated malware. Instead of tweaking configuration parameters for each new test pack or malware family, simply select a preset that matches your analysis scenario.

## What Problem Does This Solve?

**Before Presets:**
```python
# Manual tuning required for each scenario
config = DeobfuscationConfig(
    max_depth=8,
    per_string_timeout_secs=2.5,
    xor_aggressive_bruteforce=True,
    # ... 15+ more parameters to tune
)
```

**With Presets:**
```python
# One line, optimized for your scenario
config = DeobfuscationConfig.from_preset("malware_analysis")
```

## Available Presets

### 1. Conservative
**Use when:** High confidence required, low tolerance for false positives
- Strict validation (quality ≥ 0.50)
- Fewer layers (max 5)
- Faster timeout (1.5s)
- No XOR bruteforce
- No speculative decoding

**Best for:**
- Production threat intelligence
- High-stakes incident response
- Generating detection signatures

### 2. Balanced (Default)
**Use when:** General malware analysis
- Moderate validation (quality ≥ 0.45)
- Standard depth (max 6 layers)
- Standard timeout (2.0s)
- Common XOR keys only

**Best for:**
- Daily malware triage
- SOC workflows
- General deobfuscation tasks

### 3. Aggressive
**Use when:** Exploring unknown obfuscation patterns
- Loose validation (quality ≥ 0.35)
- Deep unwrapping (max 8 layers)
- Extended timeout (3.0s)
- Full XOR bruteforce
- Speculative ROT13

**Best for:**
- Research and experimentation
- Advanced persistent threats
- Novel obfuscation techniques

### 4. Malware Analysis
**Use when:** Analyzing real-world malware samples
- Optimized for PowerShell/JavaScript obfuscation
- Moderate-to-deep unwrapping (max 7 layers)
- Extended timeout (2.5s)
- Speculative ROT13 enabled

**Best for:**
- Malware lab analysis
- IOC extraction
- Reverse engineering workflows

### 5. DeepSeek Optimized
**Use when:** Testing against academic benchmarks
- Tuned for DeepSeek test pack patterns
- Moderate-to-deep unwrapping (max 7 layers)
- Extended timeout (2.5s)
- Permissive quality thresholds

**Best for:**
- Benchmark testing
- Academic research
- Validation against test suites

## Usage Examples

### Example 1: Single Preset
```python
from src.veriscope.core.deobfuscator import Deobfuscator, DeobfuscationConfig

# Create config from preset
config = DeobfuscationConfig.from_preset("malware_analysis")
deobfuscator = Deobfuscator(config)

# Deobfuscate
result = deobfuscator.deobfuscate_string(obfuscated_text)
print(f"Decoded: {result.deobfuscated[-1]}")
```

### Example 2: Preset with Overrides
```python
# Use preset but override specific settings
config = DeobfuscationConfig.from_preset("balanced", max_depth=10)
deobfuscator = Deobfuscator(config)
```

### Example 3: Automatic Preset Rotation
```python
# Try multiple presets automatically until one succeeds
deobfuscator = Deobfuscator()
result = deobfuscator.deobfuscate_with_preset_rotation(obfuscated_text)

# Which preset worked?
print(f"Success with: {result.strategy_used}")
```

### Example 4: Custom Rotation Order
```python
# Define custom preset fallback sequence
presets = ["conservative", "balanced", "aggressive"]
result = deobfuscator.deobfuscate_with_preset_rotation(
    obfuscated_text,
    presets=presets
)
```

## Preset Comparison Table

| Feature | Conservative | Balanced | Aggressive | Malware | DeepSeek |
|---------|-------------|----------|-----------|---------|----------|
| Max Depth | 5 | 6 | 8 | 7 | 7 |
| Timeout | 1.5s | 2.0s | 3.0s | 2.5s | 2.5s |
| Quality Threshold | 0.50 | 0.45 | 0.35 | 0.43 | 0.42 |
| XOR Bruteforce | ❌ | ❌ | ✅ | ❌ | ❌ |
| Speculative ROT13 | ❌ | ❌ | ✅ | ✅ | ✅ |
| False Positive Rate | Low | Medium | High | Medium | Medium |
| Coverage | Low | Medium | High | High | High |

## Command-Line Usage

### Test with Specific Preset
```bash
# Use balanced preset (default)
python test_deepseek.py

# Use aggressive preset
python test_deepseek.py -p aggressive

# Use malware_analysis preset
python test_deepseek.py --preset malware_analysis
```

### Test with Preset Rotation
```bash
# Automatically try multiple presets
python test_deepseek.py --rotate
```

## Preset Selection Guide

```
                    ┌─────────────────────────────────┐
                    │  What's your priority?          │
                    └───────────┬─────────────────────┘
                                │
                ┌───────────────┴──────────────────┐
                │                                  │
        ┌───────▼────────┐              ┌─────────▼────────┐
        │ High Confidence│              │ Maximum Coverage │
        │ Few FPs        │              │ Accept FPs       │
        └───────┬────────┘              └─────────┬────────┘
                │                                  │
        ┌───────▼────────┐              ┌─────────▼────────┐
        │ CONSERVATIVE   │              │  AGGRESSIVE      │
        └────────────────┘              └──────────────────┘

                    ┌─────────────────────────────────┐
                    │  What are you analyzing?        │
                    └───────────┬─────────────────────┘
                                │
        ┌───────────────────────┼────────────────────────┐
        │                       │                        │
┌───────▼────────┐    ┌────────▼────────┐    ┌─────────▼────────┐
│ General        │    │ Real Malware    │    │ Test Suite       │
│ Unknown Type   │    │ PowerShell/JS   │    │ Benchmark        │
└───────┬────────┘    └────────┬────────┘    └─────────┬────────┘
        │                      │                        │
┌───────▼────────┐    ┌────────▼────────┐    ┌─────────▼────────┐
│   BALANCED     │    │ MALWARE_ANALYSIS│    │ DEEPSEEK_OPT     │
└────────────────┘    └─────────────────┘    └──────────────────┘
```

## Web GUI Integration (Future)

Preset selection will be integrated into the Web GUI:

```html
<select id="preset-selector">
  <option value="conservative">Conservative (High Confidence)</option>
  <option value="balanced" selected>Balanced (Default)</option>
  <option value="aggressive">Aggressive (Max Coverage)</option>
  <option value="malware_analysis">Malware Analysis</option>
  <option value="auto">Automatic Rotation</option>
</select>
```

## Performance Impact

| Preset | Avg. Time per String | False Positive Rate | Success Rate |
|--------|---------------------|---------------------|--------------|
| Conservative | ~1.2s | 2-5% | 65-70% |
| Balanced | ~1.8s | 5-10% | 75-80% |
| Aggressive | ~2.5s | 15-20% | 85-90% |
| Rotation (Auto) | ~2-8s* | 5-10% | 80-85% |

*Depends on number of presets tried before success

## Advanced: Creating Custom Presets

```python
from src.veriscope.core.deobfuscation_presets import DeobfuscationPreset, ValidationThresholds

# Define custom thresholds
thresholds = ValidationThresholds(
    final_min_quality=0.48,
    intermediate_trigger_quality=0.50,
    # ... customize other parameters
)

# Create custom preset
custom_preset = DeobfuscationPreset(
    name="my_custom_preset",
    description="Optimized for my specific malware family",
    max_depth=9,
    per_string_timeout_secs=4.0,
    xor_aggressive_bruteforce=True,
    thresholds=thresholds
)

# Use custom preset
config = DeobfuscationConfig(
    max_depth=custom_preset.max_depth,
    per_string_timeout_secs=custom_preset.per_string_timeout_secs,
    xor_aggressive_bruteforce=custom_preset.xor_aggressive_bruteforce,
    thresholds=custom_preset.thresholds
)
```

## Troubleshooting

### Issue: "All presets failed"
**Solution:** Try manual threshold tuning for edge cases:
```python
config = DeobfuscationConfig.from_preset("aggressive", max_depth=12)
```

### Issue: Too many false positives
**Solution:** Switch to more conservative preset:
```python
config = DeobfuscationConfig.from_preset("conservative")
```

### Issue: Missing expected decodings
**Solution:** Use preset rotation to try multiple approaches:
```python
result = deobfuscator.deobfuscate_with_preset_rotation(text)
```

## Best Practices

1. **Start with Balanced**: Good for 80% of use cases
2. **Use Rotation for Unknown Samples**: Let the system find the right config
3. **Profile Your Workload**: Track which presets work best for your malware types
4. **Custom Presets for Campaigns**: Create targeted configs for specific threat actors
5. **Conservative for Production Rules**: Minimize false positives in detection signatures

## Performance Tips

- **Single Preset**: Fastest (one pass)
- **Preset Rotation**: Slower but more thorough (multiple passes with early termination)
- **Custom Order**: Balance speed vs coverage by ordering presets strategically

## Future Enhancements

- ML-based preset auto-selection
- Per-malware-family presets (e.g., "emotet", "qbot")
- Adaptive presets that learn from previous samples
- Web GUI preset management interface
