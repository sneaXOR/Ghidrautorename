<div align="center">
   
![Ghidrautorename](Ghidra.jpg)

</div>

# Ghidrautorename: Automated Function Renaming Tool for Ghidra

Ghidrautorename is a Python script that automates the process of renaming functions in Ghidra by inferring function names from debugging strings found within binary executables. This tool aims to enhance the readability and analysis of binaries by assigning more meaningful names to functions based on strings they reference.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Contributing](#contributing)
- [License](#license)

## Features

- Extracts strings from the binary executable.
- Analyzes strings to detect potential function names.
- Finds references to these strings within the code.
- Calculates a confidence score for potential function names.
- Renames functions in Ghidra based on inferred names.
- Supports multiple programming languages for source file detection.
- Optional Natural Language Processing (NLP) integration using NLTK.

## How It Works

1. **String Extraction**: The script extracts all strings from the binary that meet a minimum length requirement.

2. **Name Detection**: It uses regular expressions to identify potential function names within these strings.

3. **NLTK Processing** (Optional): If NLTK is available, the script tokenizes and tags words to improve confidence in potential function names.

4. **Reference Analysis**: For each potential function name, the script finds all references to the string in the code to determine which functions might be associated with it.

5. **Confidence Scoring**: A confidence score is calculated for each potential function name based on:
   - NLTK token relevance.
   - Rarity of the name (names appearing only once get a bonus).
   - Whether the reference is in an executable code section.

6. **Function Renaming**: Functions are renamed in Ghidra if the confidence score meets a certain threshold.

7. **Summary Output**: The script outputs a summary of renamed functions and any detected source files.

## Installation

### Prerequisites

- **Ghidra**: Download and install Ghidra from the [official website](https://ghidra-sre.org/).
- **Python 3**: Ensure you have Python 3 installed.
- **Pyhidra**: Install Pyhidra using pip:
  ```bash
  pip install pyhidra
  ```
- **NLTK** (Optional): For enhanced NLP capabilities, install NLTK:
  ```bash
  pip install nltk
  ```

### Environment Variable

Set the `GHIDRA_INSTALL_DIR` environment variable to point to the directory where Ghidra is installed.

- **Linux/MacOS**:
  ```bash
  export GHIDRA_INSTALL_DIR=/path/to/ghidra
  ```
- **Windows**:
  ```cmd
  set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
  ```

## Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/Ghidrautorename.git
   cd Ghidrautorename
   ```

2. **Run the Script**:
   ```bash
   python Ghidrautorename.py /path/to/your/binary
   ```

   Replace `/path/to/your/binary` with the actual path to the binary file you want to analyze.

## Example Output

```bash
[+] NLTK successfully imported
Total strings extracted: 7


[+] Successfully renamed function at 0x08048a86 to 'Exemple'

==================================================
Summary of Renamed Functions
==================================================

Function at 0x08048a86 renamed to Exemple

==================================================
Renaming Process Complete
==================================================
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
