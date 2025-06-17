# Phase 3: Enigma Challenge Walkthrough

## Overview

This phase covers steganography, historical cryptography, audio forensics, and metadata extraction. Participants must discover a hidden file, extract embedded data, decrypt messages, and recover the final flag from audio metadata.

## Prerequisites
- Familiarity with process monitoring tools (e.g., Procmon)
- Experience with hex editors and file format analysis
- Understanding of Enigma cipher basics
- Ability to use audio forensics tools

## Step-by-Step Solution

1. **File Discovery via Process Monitoring**
   - Use Procmon (or similar) to monitor the challenge process (e.g., `dronespy.exe`).
   - Discover the creation of a hidden PNG file at `C:/Users/Public/Open-Me.png`.

2. **Steganographic Extraction from PNG**
   - Open the PNG file in a hex editor (e.g., HxD, ghex).
   - Locate appended data after the PNG image: look for `-----ENIGMA_CONFIG_START-----` and `-----ENIGMA_CONFIG_END-----` markers.
   - Extract the Enigma configuration and the following base64-encoded audio data.

3. **Enigma Configuration Parsing and Decryption**
   - Parse the Enigma configuration string (rotors, reflector, plugboard settings).
   - Use an Enigma simulator or implement your own to decrypt the provided spy messages.
   - Example message: `xasnf faybk latqe ku 64` → "The string is on base 64".

4. **Base64 Audio Decode**
   - Decode the extracted base64 string to obtain an MP3 file.

5. **Audio Metadata Forensics**
   - Use an MP3 metadata tool (e.g., Mp3tag, exiftool) to inspect the ID3 tags of the MP3 file.
   - The final flag is embedded as Morse code in the metadata.
   - Decode the Morse code to reveal the flag.

## Troubleshooting
- **Can't find the PNG file?**
  - Double-check process monitoring filters and ensure the challenge process is running.
- **Data not visible in hex editor?**
  - Scroll past the end of the PNG image data to find the appended sections.
- **Enigma decryption not working?**
  - Verify rotor/plugboard settings and message formatting.
- **No flag in audio?**
  - Ensure you are inspecting the ID3 metadata, not just the audio content.

## Reference
- See `tls/server_challenges/enigma_challenge.py` and `utils/audio_data.py` for implementation details.
- Use Procmon, hex editors, Enigma simulators, and MP3 metadata tools as described above.
