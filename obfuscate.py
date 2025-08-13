#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import random
import string
import re
from itertools import product

# ----------------------------
# Constants & helpers
# ----------------------------

END_SYMBOLS = [' ', '\\', '\n', '.', ',', ';', '=', '`', '"', "'", '(', ')', ':', '[', ']', '{', '}', '+']  # no ++
END_SYMBOLS_BY_2 = list(product(END_SYMBOLS, END_SYMBOLS))


def _prev_char(s, i):
    return s[i - 1] if i - 1 >= 0 else None


def _next_end_index(s, start, end_symbols):
    """
    Return absolute index of the earliest end symbol after `start`.
    If none is found, return len(s).
    """
    best = len(s)
    for es in end_symbols:
        j = s.find(es, start + 1)
        if j != -1 and j < best:
            best = j
    return best


def _is_followed_by_end(s, j):
    """True if j is out of range or char at j is an END_SYMBOL."""
    return j >= len(s) or s[j] in END_SYMBOLS


# ----------------------------
# Random helpers
# ----------------------------

def random_string():
    """Generate a random string of fixed length"""
    length = random.randint(5, 30)
    letters = string.ascii_lowercase + string.ascii_uppercase
    return ''.join(random.choice(letters) for _ in range(length))


def random_bits(length):
    """Generate a random 1/0 string of fixed length"""
    chars = '01'
    return ''.join(random.choice(chars) for _ in range(length))


def randomize_case(input_string):
    """Randomly change the case of each letter of the input_string"""
    rand_bits = random_bits(len(input_string))
    return ''.join(
        input_string[i].lower() if rand_bits[i] == '0' else input_string[i].upper()
        for i in range(len(input_string))
    )


# ----------------------------
# Core logic
# ----------------------------

def delete_comments(input_text):
    """
    Completely delete comments in the input_text.
    Type 1 comments: "<# ... #>".
    Type 2 comments: "# ... \n", except when # is inside " or ' on that line (heuristic).
    """
    output = ''
    start_symbols = ['<#', '#']
    end_symbols = ['#>', '\n']
    assert len(start_symbols) == len(end_symbols)

    for i in range(len(start_symbols)):
        output = ''

        # initial search
        start_index = input_text.find(start_symbols[i])

        while start_index >= 0:
            # handle indentation before the comment (spaces/tabs)
            last_line = input_text[:start_index].split('\n')[-1]
            if last_line.strip() == "":
                if len(last_line) > 0:
                    start_index = start_index - len(last_line)

            # append everything up to start_index
            output += input_text[:start_index]

            # decide whether to treat as a real comment
            treat_as_comment = True
            if i == 1:
                # single-line '#' comments — skip if escaped or inside quotes (rough heuristic)
                prev_c = _prev_char(input_text, start_index)
                if prev_c == "`":
                    treat_as_comment = False
                else:
                    # crude: if both sides of the '#' on the same line contain quotes, assume inside quotes
                    left = input_text[:start_index].split('\n')[-1]
                    right = input_text[start_index:].split('\n')[0]
                    if (("'" in left and "'" in right) or ('"' in left and '"' in right)):
                        treat_as_comment = False

            if treat_as_comment:
                # skip the comment until its end symbol (or EoF if not found)
                rel = input_text[start_index:].find(end_symbols[i])
                if rel == -1:
                    end_index = len(input_text)
                else:
                    end_index = start_index + rel + len(end_symbols[i])
            else:
                # not a real comment; keep the symbol and advance one char
                end_index = start_index + 1
                output += input_text[start_index:end_index]

            # cut and continue
            input_text = input_text[end_index:]
            start_index = input_text.find(start_symbols[i])

        output += input_text
        input_text = output

    # normalize excessive blank lines gently
    while '\n\n\n' in output:
        output = output.replace('\n\n\n', '\n\n')
    return output


def rename_variables(input_text):
    """
    Randomly rename variables in input_text and return the result with a mapping table.

    Returns: (string, dict) => (text_with_renamed_vars, mapping_dict)
      mapping_dict keys are original variable names (lowercased, with leading $),
      values are the randomized replacements (without leading $).
    """
    start_symbol = '$'

    powershell_auto_vars = [
        '$NestedPromptLevel', '$PSBoundParameters', '$ExecutionContext', '$ConsoleFileName',
        '$EventSubscriber', '$SourceEventArgs', '$PSDebugContext', '$PsVersionTable',
        '$PSCommandPath', '$LastExitCode', '$MyInvocation', '$PSScriptRoot', '$PSSenderInfo',
        '$PsUICulture', '$SourceArgs', '$StackTrace', '$EventArgs', '$PsCulture', '$Allnodes',
        '$PsCmdlet', '$ForEach', '$Matches', '$Profile', '$ShellID', '$PsHome', '$PSitem',
        '$Sender', '$Error', '$Event', '$False', '$Input', '$Args', '$Home', '$Host', '$NULL',
        '$This', '$True', '$OFS', '$PID', '$Pwd', '$$', '$?', '$^', '$_', '$('  # keep '$(' intact
    ]

    powershell_system_vars = [
        'Advapi32', 'AccessMask', 'AppDomain', 'Architecture', 'AssemblyName', 'Assembly',
        'BatPath', 'B64Binary', 'BackupPath', 'BindingFlags', 'binPath', 'Bitfield',
        'CallingConvention', 'Charset', 'CheckAllPermissionsInSet', 'Class', 'Command',
        'Credential', 'CurrentUser', 'CustomAttributeBuilder', 'DllBytes', 'DllImportAttribute',
        'DllName', 'DllPath', 'Emit', 'EntryPoint', 'EnumElements', 'ExcludeProgramFiles', 'Env',
        'ExcludeWindows', 'ExcludeOwned', 'FieldInfo', 'FieldName', 'FieldProp', 'Field', 'File',
        'Filter', 'Force', 'FunctionDefinitions', 'FunctionName', 'GetServiceHandle',
        'InteropServices', 'Kernel32', 'Keys', 'KeyName', 'KnownDLLs', 'LiteralPaths',
        'LocalGroup', 'MarshalAsAttribute', 'MarshalAs', 'Marshal', 'ModuleBuilder', 'ModuleName',
        'Module', 'Namespace', 'Name', 'NativeCallingConvention', 'NewField', 'Offset',
        'OpCodes', 'Out', 'Owners', 'PackingSize', 'ParameterTypes', 'PasswordToAdd', 'Password',
        'Path', 'PermissionSet', 'Permissions', 'Position', 'ProcessName', 'PropertyInfo',
        'Properties', 'ReadControl', 'ReplaceString', 'Runtime', 'ReturnType', 'SearchString',
        'ServiceAccessRights', 'ServiceCommand', 'ServiceCommands', 'ServiceDetails',
        'ServiceName', 'Service', 'SetLastError', 'SID_AND_ATTRIBUTES', 'SidAttributes',
        'SizeConst', 'StructBuilder', 'System', 'TargetPermissions', 'TargetService',
        'TOKEN_GROUPS', 'TokenGroups', 'TypeAttributes', 'TypeHash', 'Types', 'Type',
        'UnmanagedType', 'UserNameToAdd'
    ]

    powershell_auto_system_vars = powershell_auto_vars + ['$' + i for i in powershell_system_vars]

    # Pre-scan to find child names of system vars that should not be replaced
    not_to_replace_dict = {}
    lt = input_text.lower()
    for system_var in powershell_system_vars:
        token = '$' + system_var.lower()
        if token in lt:
            # Protect children like $System.Name => don't rename $Name if it appears as a property paired with a $child
            dot_idx = lt.find(token + '.')
            if dot_idx > -1:
                # after the dot
                after = dot_idx + len(token) + 1
                # extract child token up to the next end symbol
                child_end = _next_end_index(lt, after - 1, END_SYMBOLS)  # -1 so it starts searching from 'after'
                child = input_text[after:child_end]
                if child:
                    cand = '$' + child.lower()
                    if cand not in not_to_replace_dict:
                        # verify the pair ".child" and "$child" occur in plausible positions
                        for end_symbol_a, end_symbol_b in END_SYMBOLS_BY_2:
                            if ('.' + child.lower() + end_symbol_a) in lt and (cand + end_symbol_b) in lt:
                                not_to_replace_dict[cand] = None
                                break

    input_text_raw = input_text  # keep original for context tests if needed
    vars_dict = {}
    output = ''

    # scanning loop
    start_index = input_text.find(start_symbol)
    start_index_raw = start_index

    while start_index >= 0:
        # append everything up to start_index
        output += input_text[:start_index]

        # quote-state heuristic (keep original behavior, but safer)
        in_single_heur = (
            (input_text_raw[:start_index_raw].count("'")
             - input_text_raw[:start_index_raw].count("`'")
             - input_text_raw[:start_index_raw].count('"\'"')) % 2 != 0
        )
        in_double_heur = (
            (input_text_raw[:start_index_raw].count('"')
             - input_text_raw[:start_index_raw].count('`"')
             - input_text_raw[:start_index_raw].count("'\"'")) % 2 != 0
        )

        prev_c = _prev_char(input_text, start_index)
        next_c = input_text[start_index + 1] if (start_index + 1) < len(input_text) else None

        # Cases we deliberately do NOT treat as variable starts
        if (in_single_heur and not in_double_heur) or prev_c == '`' or next_c in END_SYMBOLS or next_c is None:
            # false positive: keep '$' and move on by 1
            end_index = start_index + 1
            output += "$"
        else:
            # Parse the variable token
            token_start = start_index
            var_token = '$'
            var_name = None  # without '$' and braces
            token_end = start_index + 1

            if next_c == '{':
                # ${var}
                close = input_text.find('}', start_index + 2)
                if close != -1:
                    var_name = input_text[start_index + 2:close]
                    var_token = input_text[start_index:close + 1]  # include braces
                    token_end = close + 1
                else:
                    # unmatched '{' — treat '$' as normal char
                    end_index = start_index + 1
                    output += "$"
                    input_text = input_text[end_index:]
                    # advance raw pointers
                    offset = end_index - start_index
                    start_index = input_text.find(start_symbol)
                    start_index_raw = start_index_raw + offset + (start_index if start_index != -1 else len(input_text))
                    continue
            else:
                # $name
                token_end = _next_end_index(input_text, start_index, END_SYMBOLS)
                var_token = input_text[start_index:token_end]
                var_name = var_token[1:]

            # Reserved / auto vars: leave untouched
            # Normalize to $name form for comparison
            comp_token = ('$' + var_name) if var_name is not None else var_token
            is_reserved = any(comp_token.lower() == ev.lower() for ev in powershell_auto_system_vars)

            # Avoid renaming risky/system-like children detected earlier
            skip_by_child = (comp_token.lower() in not_to_replace_dict)

            if is_reserved or skip_by_child or not var_name:
                output += var_token
                end_index = token_end
            else:
                key = comp_token.lower()  # store as $name (lowercased)
                if key not in vars_dict:
                    vars_dict[key] = random_string()

                new_name = vars_dict[key]
                if var_token.startswith('${'):
                    # preserve brace form
                    output += '${' + new_name + '}'
                else:
                    output += '$' + new_name
                end_index = token_end

        # cut processed chunk
        input_text = input_text[end_index:]
        # advance raw pointer consistently
        offset = end_index - start_index
        # find next
        start_index = input_text.find(start_symbol)
        start_index_raw = start_index_raw + offset + (start_index if start_index != -1 else len(input_text))

    output += input_text

    # IMPORTANT: Removed dangerous passes that renamed parameter names, properties, and quoted identifiers.
    # (Original steps 6–8). Those caused widespread breakage.

    return output, vars_dict


def main(input_text):
    v_dict, f_dict = {}, {}
    output1 = delete_comments(input_text)
    output2, v_dict = rename_variables(output1)
    return output1, output2, v_dict, f_dict


if __name__ == '__main__':
    old_file = 'PowerUp.ps1 - Source.txt'

    base, ext = os.path.splitext(old_file)
    new_semi_obfs_file = f'{base} - semi-obfuscated{ext}'
    new_obfs_file = f'{base} - obfuscated{ext}'

    with open(old_file, 'r', encoding='utf-8') as fr:
        input_data = fr.read()

    semi_obfs_data, obfs_data, vars_dict, funcs_dict = main(input_data)

    with open(new_semi_obfs_file, 'w', encoding='utf-8') as f:
        f.write(semi_obfs_data)

    with open(new_obfs_file, 'w', encoding='utf-8') as f:
        f.write(obfs_data)

    # mapping output
    vd = sorted([' - '.join(i) for i in vars_dict.items()])
    fd = sorted([' - '.join(i) for i in funcs_dict.items()])
    mapping = 'Functions: \n' + '\n'.join(fd) + '\n\n\nVariables: \n' + '\n'.join(vd)

    with open(new_obfs_file + ' - name mapping.txt', 'w', encoding='utf-8') as f:
        f.write(str(mapping))
