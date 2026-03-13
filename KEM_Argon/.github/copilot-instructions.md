<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->
- [x] Project requirements clarified: Particle Argon, ML-KEM, MQTT, UART, WiFi, RGB LED
- [x] Project scaffolded in ML-KEM_Argon directory
- [ ] Customize the project: Copy and adapt code from ESP32 version
- [ ] Install required extensions: None needed for Particle OS
- [ ] Compile the project: Use Particle Workbench or CLI
- [ ] Create and run task: Add build/flash task if needed
- [ ] Launch the project: Flash to Argon and run
- [ ] Ensure documentation is complete: README.md and copilot-instructions.md

## Execution Guidelines
- Use Particle Device OS APIs
- Remove ESP-IDF/FreeRTOS dependencies
- Map pins to Argon (D0-D8, A0-A5)
- Use Particle WiFi, MQTT, Serial, RGB APIs
- Use C++ STL for queue abstraction
- Keep communication concise
