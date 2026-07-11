# Implicit Max routing

The vulnerable harness makes Max the persistent default, so every ordinary task inherits its
cost and latency. The guarded twin keeps Medium as the default and moves Max into a separately
selected profile. This pair exercises `CDX-D7-03` and `CDX-D7-04`; neither check is a capability
gate, so the proof is the exact D7 and overall-score delta rather than a grade cap.
