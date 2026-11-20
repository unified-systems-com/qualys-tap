# Qualys TAP

A read-only collector for Qualys VMDR, a plugin for [TAP](https://github.com/unified-systems-com/tap). It reads the host detections Qualys holds (from Cloud Agents and scanner appliances) and the QID knowledge base behind them. It lands them on the grid in Qualys's own shape, linked to the AWS EC2 instances they concern.

The specification arrives first, on the `spec/qualys-v0` branch; the package follows from it.

Licensed under the Apache License 2.0.
