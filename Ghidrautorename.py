import argparse
import re
import pyhidra

# Importing Ghidra modules directly
from ghidra.program.model.data import StringDataType
from ghidra.program.model.symbol import SourceType

# Regular expressions for detecting function names and source files
FUNCTION_NAMES_REGEXP = r"([a-zA-Z_][a-zA-Z0-9_]+(?:::[a-zA-Z_][a-zA-Z0-9_]+)*)"
CLASS_NAMES_REGEXP = r"([a-z_][a-z0-9_]+(?:::(?:<[a-z0-9_]+>|~?[a-z0-9_]+))+)\(?"
SOURCE_FILES_REGEXP = r"([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(?:c|cc|cxx|cpp|h|hpp|m|rs|go|ml))(?=$|:| )"

LANGS = {
    "C/C++": ["c", "cc", "cxx", "cpp", "h", "hpp"],
    "Rust": ["rs"],
    "Golang": ["go"],
    "OCaml": ["ml"]
}

NOT_FUNCTION_NAMES = {
    "copyright", "char", "bool", "int", "unsigned", "long", "double", "float",
    "signed", "license", "version", "cannot", "error", "invalid", "null",
    "warning", "general", "argument", "written", "report", "failed", "assert",
    "object", "integer", "unknown", "localhost", "native", "memory", "system",
    "write", "read", "open", "close", "help", "exit", "test", "return",
    "libs", "home", "ambiguous", "internal", "request", "deleting", "adding"
}

CONFIDENCE_SCORES = {}

# Optional NLP setup
try:
    import nltk
    from nltk.tokenize import word_tokenize
    nltk.download('averaged_perceptron_tagger', quiet=True)
    from nltk.tag import pos_tag
    HAS_NLTK = True
    print("[+] NLTK successfully imported")
except ImportError:
    print("[!] NLTK not available. Continuing without NLP.")
    HAS_NLTK = False

TOKEN_TYPES = {"NN", "NNS", "NNP", "JJ", "VB", "VBD", "VBG", "VBN", "VBP", "VBZ"}
FOUND_TOKENS = {}

# Function to process and tag words using NLTK
def nltk_preprocess(strings):
    if not HAS_NLTK:
        return

    tokens = re.findall(FUNCTION_NAMES_REGEXP, "\n".join(strings))
    token_list = [token for token in tokens if token.lower() not in NOT_FUNCTION_NAMES]
    word_tags = pos_tag(token_list)

    for word, tag in word_tags:
        word_lower = word.lower()
        if tag in TOKEN_TYPES:
            FOUND_TOKENS[word_lower] = tag
            # Increase confidence if NLTK detects a relevant name
            CONFIDENCE_SCORES[word_lower] = CONFIDENCE_SCORES.get(word_lower, 0) + 1

# Function to calculate the final confidence of a name
def calculate_confidence(potential_name, references):
    score = 0
    name_lower = potential_name.lower()

    # NLTK factor (if it detected relevant tokens)
    if name_lower in CONFIDENCE_SCORES:
        score += CONFIDENCE_SCORES[name_lower]

    # Rarity factor: the rarer a name, the higher the confidence
    if len(references) == 1:
        score += 2  # Confidence bonus if the name appears only once

    # Additional score if the name is in an executable section
    if all(check_address_in_code_section(currentProgram, ref.getEntryPoint()) for ref in references):
        score += 1

    return score

# Extract function name from string
def extract_function_name_from_string(string_content, string_address):
    if HAS_NLTK:
        nltk_preprocess([string_content])

    potential_name = None
    class_match = re.search(CLASS_NAMES_REGEXP, string_content)
    if class_match:
        potential_name = class_match.group(0)

    if not potential_name:
        function_match = re.search(FUNCTION_NAMES_REGEXP, string_content)
        if function_match:
            potential_name = function_match.group(0)

    if not potential_name or potential_name.lower() in NOT_FUNCTION_NAMES:
        return None

    references = find_references_to_string(string_address)
    confidence = calculate_confidence(potential_name, references)

    # Check if confidence is sufficient
    if confidence < 2:  # Only rename if confidence >= 2
        return None

    return potential_name

# Extract source file name from string
def extract_source_file_from_string(string_content):
    match = re.search(SOURCE_FILES_REGEXP, string_content)
    if match:
        file_name = match.group(0)
        lang = determine_language(file_name)
        return file_name, lang
    return None, None

# Determine the language of a file
def determine_language(file_name):
    for lang, extensions in LANGS.items():
        if any(file_name.endswith(ext) for ext in extensions):
            return lang
    return "Unknown"

# Function to categorize and detect function names
def categorize_function_names(strings_list):
    func_names = {}
    candidates = {}

    for string_address, string_content in strings_list:
        potential_name = extract_function_name_from_string(string_content, string_address)
        if potential_name:
            references = find_references_to_string(string_address)
            for ref in references:
                func_addr = ref.getEntryPoint()
                if func_addr not in func_names:
                    func_names[func_addr] = set()
                func_names[func_addr].add(potential_name)

    for func_addr, names in func_names.items():
        if names:
            candidates[func_addr] = list(names)[0]

    return candidates

# Extract strings from binary
def extract_strings(min_length=4):
    listing = currentProgram.getListing()
    strings = []

    for data in listing.getDefinedData(True):
        try:
            if data.isDefined() and isinstance(data.getDataType(), StringDataType):
                string_value = data.getValue()
                if len(string_value) >= min_length:
                    strings.append((data.getAddress(), string_value))
        except Exception as e:
            print(f"[!] Error processing data: {e}")

    print(f"Total strings extracted: {len(strings)}")
    return strings

# Check if an address is in an executable code section
def check_address_in_code_section(currentProgram, address):
    memory_blocks = currentProgram.getMemory().getBlocks()
    for block in memory_blocks:
        if block.isExecute() and block.contains(address):
            return True
    return False

# Find cross-references to strings
def find_references_to_string(string_address):
    references = currentProgram.getReferenceManager().getReferencesTo(string_address)
    if not references:
        return []

    functions = []
    for ref in references:
        if ref is None:
            continue

        from_address = ref.getFromAddress()
        if from_address is None:
            continue

        if check_address_in_code_section(currentProgram, from_address):
            function = getFunctionContaining(from_address)
            if function:
                functions.append(function)
    return functions

# Check if a function name already exists
def function_exists_with_name(new_name):
    symbol_table = currentProgram.getSymbolTable()
    exists = symbol_table.getSymbols(new_name).hasNext()
    return exists

# Check if the function has a valid EntryPoint
def check_function_entry_point(function):
    entry_point = function.getEntryPoint()
    if entry_point is None:
        return False
    return True

# Rename function in Ghidra
def rename_function_in_ghidra(function, new_name):
    if not function or not new_name or len(new_name) < 3:
        return False

    if function_exists_with_name(new_name):
        return False

    if not check_function_entry_point(function):
        return False

    try:
        # Use setName() to rename the function
        function.setName(new_name, SourceType.USER_DEFINED)
        print(f"[+] Successfully renamed function at {function.getEntryPoint()} to '{new_name}'")
        return True
    except Exception as e:
        print(f"[!] Failed to rename function at {function.getEntryPoint()}: {e}")
        return False

# Rename functions based on detected candidates
def rename_functions_based_on_candidates(strings_list):
    renamed_functions = set()
    candidates = categorize_function_names(strings_list)

    for func_addr, candidate_name in candidates.items():
        function = getFunctionAt(func_addr)
        if function is None:
            continue

        references = find_references_to_string(func_addr)
        confidence = calculate_confidence(candidate_name, references)

        if confidence >= 2:
            if rename_function_in_ghidra(function, candidate_name):
                renamed_functions.add(function)

    return renamed_functions

# Summarize renamed functions
def summarize_renamed_functions(renamed_functions):
    print_header("Summary of Renamed Functions")
    for func in renamed_functions:
        print(f"Function at {func.getEntryPoint()} renamed to {func.getName()}")

# Summarize source files
def summarize_source_files(source_files):
    if not source_files:
        return
    print_header("Summary of Source Files")
    for source_file, lang in source_files.items():
        print(f"Source file: {source_file} (Language: {lang})")

# Main process to optimize and rename functions
def rename_functions_with_optimizations():
    all_strings = extract_strings()
    if not all_strings:
        print("[!] No strings found!")
        return

    # Rename functions based on candidates
    renamed_functions = rename_functions_based_on_candidates(all_strings)

    # Extract potential source files
    source_files = {}
    for _, string_content in all_strings:
        source_file, lang = extract_source_file_from_string(string_content)
        if source_file:
            source_files[source_file] = lang

    # Summarize the renaming process
    summarize_source_files(source_files)
    summarize_renamed_functions(renamed_functions)
    print_header("Renaming Process Complete")

# Helper function to format output in the console
def print_header(header):
    print("\n" + "=" * 50)
    print(f"{header}")
    print("=" * 50 + "\n")

# Main function
def main(binary_path):
    with pyhidra.open_program(binary_path) as flat_api:
        global currentProgram
        currentProgram = flat_api.getCurrentProgram()

        global getFunctionAt, getFunctionContaining
        getFunctionAt = flat_api.getFunctionAt
        getFunctionContaining = flat_api.getFunctionContaining

        # Execute the main optimization and renaming function
        rename_functions_with_optimizations()

# Entry point of the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated function renaming using Pyhidra.")
    parser.add_argument("binary_path", help="Path to the binary file to analyze")

    args = parser.parse_args()
    main(args.binary_path)
