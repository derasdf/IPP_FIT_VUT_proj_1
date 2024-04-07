# Code made by Aleksandrov Vladimir xaleks03
import sys
import re
import xml.etree.ElementTree as ET
import xml.dom.minidom as MINI
import argparse


# Function to add argument element to an instruction
def add_arg_element(instruction, arg_name, arg_type, arg_value):
    arg = ET.SubElement(instruction, arg_name)
    # Validation for string type argument
    if arg_type == "string":
        pattern_string = re.compile(r"^(?:[^\\]*(?:\\\d{3})?)*$")
        if pattern_string.match(arg_value) is None:
            raise LexEx("Wrong string")
    # Validation for integer type argument
    if arg_type == "int":
        pattern_string = re.compile(
            r"^(?:-?\+?\d+|-?\+?0o[0-7]+(?:\.[0-7]+)?|-?\+?0x[0-9a-fA-F]+)$"
        )
        if pattern_string.match(arg_value) is None:
            raise LexEx("Wrong int")
    # Validation for boolean type argument
    if arg_type == "bool":
        if arg_value != "true" and arg_value != "false":
            raise LexEx("Wrong bool")
    # Validation for nil type argument
    if (arg_type == "nil" and arg_value != "nil") or (
        arg_value == "nil" and arg_type != "nil"
    ):
        raise LexEx("Wrong nil")
    # Handling variable types and scopes
    if arg_type in allowed_scopes:
        if pattern_bad.match(arg_value) is None:
            raise LexEx("Wrong symbol")
        arg.set("type", "var")
        arg.text = f"{arg_type}@{arg_value}"
    else:
        arg.set("type", arg_type)
        arg.text = arg_value


# Function to check variable and scope validity
def check_var(var_name, scope_name):
    if var_name in first_var and scope_name not in allowed_scopes:
        raise LexEx("Wrong keyword")


# Custom Exceptions
class HeaderEx(Exception):
    pass


class OpCodeEx(Exception):
    pass


class LexEx(Exception):
    pass


# Command line arguments handling
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument(
    "--help",
    action="store_true",
    help="Display this help message and exit.\n\
This script reads instructions in the .IPPcode24 format from the standard input, validates them, and generates an XML representation of the program.\n\
Each instruction consists of an operation code (opcode) and its arguments.\n\
The script validates the correctness of the opcode and its arguments according to the specified rules.\n\
If the input format is incorrect or contains invalid instructions, appropriate error messages will be displayed.\n\
\n\
Error codes and descriptions:\n\
10 - Wrong arguments: The script encountered incorrect amount of arguments.\n\
21 - Missing or incorrect header in the source code written in IPPcode24.\n\
22 - Unknown or incorrect operation code in the source code written in IPPcode24.\n\
23 - Other lexical or syntactic error in the source code written in IPPcode24.\n",
)

# Handling help argument
args = parser.parse_args()

if args.help:
    if len(sys.argv) > 2:
        sys.exit(10)
    parser.print_help()
    sys.exit(0)

# Allowed instructions and types
allowed_first = {
    "CREATEFRAME",
    "PUSHFRAME",
    "POPFRAME",
    "RETURN",
    "BREAK",
}
allowed_second = {"WRITE", "DEFVAR", "PUSHS", "POPS", "EXIT", "DPRINT"}
allowed_labels = {"JUMP", "CALL", "LABEL"}
allowed_labels_big = {"JUMPIFEQ", "JUMPIFNEQ"}
allowed_third = {"READ", "NOT", "MOVE", "INT2CHAR", "STRLEN", "TYPE"}
allowed_four = {
    "CONCAT",
    "ADD",
    "SUB",
    "MUL",
    "IDIV",
    "AND",
    "OR",
    "EQ",
    "GT",
    "LT",
    "STRI2INT",
    "GETCHAR",
    "SETCHAR",
}
allowed_var_types = {"int", "string", "bool", "nil"}
allowed_scopes = {"GF", "TF", "LF"}
allowed_types = allowed_var_types | allowed_scopes
first_var = {
    "MOVE",
    "READ",
    "DEFVAR",
    "POPS",
    "NOT",
    "INT2CHAR",
    "STRLEN",
    "TYPE",
} | allowed_four

allowed_all = (
    allowed_first
    | allowed_second
    | allowed_labels
    | allowed_third
    | allowed_types
    | allowed_labels_big
    | allowed_four
    | {".IPPcode24"}
)
# Regular expressions for pattern matching
pattern_bad = re.compile(r"^(?![0-9])[_\-$&%*!?a-zA-Z0-9]+$")
pattern_all = re.compile(rf"({'|'.join(allowed_all)})\b(.*?)", re.IGNORECASE)
pattern_empty = re.compile(rf"\s*(?:#.*)?$")
pattern1 = re.compile(rf"^(.IPPcode24){pattern_empty.pattern}$")
pattern11 = re.compile(rf"^(\w+){pattern_empty.pattern}$")
pattern_types = re.compile(rf"({'|'.join(allowed_types)})@([^#\s]*)")
pattern_labels = re.compile(rf"^(\w+)\s+([^\s]+){pattern_empty.pattern}$")
pattern_labels_big = re.compile(
    rf"^(\w+)\s+(\w+)\s+{pattern_types.pattern}\s+{pattern_types.pattern}{pattern_empty.pattern}$"
)
pattern2 = re.compile(rf"^(\w+)\s+{pattern_types.pattern}|{pattern_empty.pattern}$")
pattern22 = re.compile(rf"^(\w+)\s+{pattern_types.pattern}{pattern_empty.pattern}$")
pattern3 = re.compile(
    rf"^(\w+)\s+{pattern_types.pattern}\s+({'|'.join(allowed_types)})(?:\s*@([^#\s]*))?{pattern_empty.pattern}$"
)
pattern4 = re.compile(
    rf"^(\w+)\s+{pattern_types.pattern}\s+{pattern_types.pattern}\s+{pattern_types.pattern}{pattern_empty.pattern}$"
)

# Main program execution
try:
    line = input().strip()
    while pattern_empty.match(line):
        line = input().strip()

    match = pattern1.match(line)
    if not match:
        raise HeaderEx("Expected '.IPPcode24'")

    root = ET.Element("program")
    root.set("language", "IPPcode24")
    order = 0

    while True:
        try:
            line = input().strip()

            match = pattern_empty.match(line)

            if match is not None:
                continue
            elif (match := pattern_all.match(line)) is not None:
                opcode = match.group(1).upper()
                if opcode == ".IPPCODE24":
                    raise LexEx("Wrong keyword")
                order += 1
                instruction = ET.SubElement(root, "instruction")
                instruction.set("order", str(order))
                instruction.set("opcode", opcode)
                if opcode in allowed_first and (
                    match := pattern11.match(line) is not None
                ):
                    continue

                if opcode in allowed_labels | allowed_labels_big:
                    if (match := pattern_labels.match(line)) is not None or (
                        match := pattern_labels_big.match(line)
                    ) is not None:
                        label_check = re.compile(r"^[^@]*$")
                        if (
                            label_check.match(match.group(2)) is None
                            or pattern_bad.match(match.group(2)) is None
                        ):
                            raise LexEx("Wrong keyword")

                        add_arg_element(instruction, "arg1", "label", match.group(2))
                        if opcode in allowed_labels:
                            continue
                        if (match := pattern_labels_big.match(line)) is not None:

                            add_arg_element(
                                instruction, "arg2", match.group(3), match.group(4)
                            )
                            add_arg_element(
                                instruction, "arg3", match.group(5), match.group(6)
                            )
                elif opcode in allowed_second | allowed_third | allowed_four:

                    if (match := pattern2.match(line)) is not None:
                        check_var(opcode, match.group(2))
                        add_arg_element(
                            instruction, "arg1", match.group(2), match.group(3)
                        )
                        if (
                            opcode in allowed_second
                            and (match := pattern22.match(line)) is not None
                        ):
                            continue
                        match = None
                        if (
                            pattern3.match(line)
                        ) is not None and opcode in allowed_third:
                            match = pattern3.match(line)
                            if match.group(5) is not None:
                                add_arg_element(
                                    instruction, "arg2", match.group(4), match.group(5)
                                )

                            else:
                                add_arg_element(
                                    instruction, "arg2", "type", match.group(4)
                                )

                            if opcode == "READ" and (
                                match.group(2) not in allowed_scopes
                                or match.group(4) not in allowed_var_types
                                or match.group(5) is not None
                            ):
                                raise LexEx("Wrong keyword")
                            continue
                        if (
                            pattern4.match(line)
                        ) is not None and opcode in allowed_four:
                            match = pattern4.match(line)
                            add_arg_element(
                                instruction, "arg2", match.group(4), match.group(5)
                            )
                            add_arg_element(
                                instruction, "arg3", match.group(6), match.group(7)
                            )
                if not match:
                    raise LexEx("Wrong keyword")
            if not match:
                raise OpCodeEx("Wrong keyword")
        except EOFError:
            break

    xml_str = ET.tostring(root, encoding="UTF-8")
    parsed_xml = MINI.parseString(xml_str)
    pretty_xml = parsed_xml.toprettyxml(indent="    ", encoding="UTF-8").decode("UTF-8")

    print(pretty_xml)


except HeaderEx as ve:
    sys.exit(21)
except OpCodeEx as ve:
    sys.exit(22)
except LexEx as ve:
    sys.exit(23)
except EOFError:
    sys.exit(21)
