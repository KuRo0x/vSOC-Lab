# Improvements Implemented

## Network Controls
- Replaced hardcoded IP blocking with IOC-based firewall aliases
- Consolidated HTTP and HTTPS blocking into a single rule
- Ensured containment rules are prioritized above general allow rules

## Process Improvements
- Formalized IOC handling using aliases to support future indicators
- Documented containment actions for repeatability
- Integrated lessons learned into the SOC playbook