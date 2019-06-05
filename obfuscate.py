#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import string
import re
from itertools import product


END_SYMBOLS = [' ', '\\', '\n', '.', ',', ';', '=', '`', '"', "'", '(', ')', ':', '[', ']', '{', '}', '+']  # no ++
END_SYMBOLS_BY_2 = list(product(END_SYMBOLS, END_SYMBOLS))


def random_string():
    """Generate a random string of fixed length """
    length = random.randint(5, 30)
    letters = string.ascii_lowercase + string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(length))


def random_bits(length):
    """Generate a random 1/0 string of fixed length """
    chars = '01'
    return ''.join(random.choice(chars) for i in range(length))


def randomize_case(input_string):
    """Randomly change the case of each letter of the input_string"""
    rand_bits = random_bits(len(input_string))
    return ''.join(input_string[i].lower() if rand_bits[i] == '0' else
                   input_string[i].upper()
                   for i in range(len(input_string)))


def delete_comments(input_text):
    """
    Completely delete all the comments in the input_text.
    Type 1 comments: "<# ... #>".
    Type 2 comments: "# ... \n", except for cases when # is surrounded with " or '.
    :param input_text: a string representing a script to work on.
    :return: an input_text freed from any comments.
    """
    output = ''
    start_symbols = ['<#', '#']
    end_symbols = ['#>', '\n']
    assert len(start_symbols) == len(end_symbols)
    for i in range(len(start_symbols)):
        output = ''
        # 1. initial search
        start_index = input_text.find(start_symbols[i])
        while start_index >= 0:
            if input_text[:start_index].split('\n')[-1].replace(" ", "") == "":  # handling spaces before the comment
                if len(input_text[:start_index].split('\n')[-1]) > 0:
                    start_index = start_index - len(input_text[:start_index].split('\n')[-1])
            # 2. append everything up to start_index to the output
            output = output + input_text[:start_index]
            # 3. then, either:
            if i == 0 or (i == 1 and input_text[start_index - 1] != "`" and
                          ((input_text[:start_index].split('\n')[-1].find("'") == -1 or
                           input_text[start_index:].split('\n')[0].find("'") == -1) and
                           (input_text[:start_index].split('\n')[-1].find('"') == -1 or
                           input_text[start_index:].split('\n')[0].find('"') == -1))):
                # 3.1. skip the comment
                end_index = start_index + input_text[start_index:].find(end_symbols[i]) + len(end_symbols[i])
            else:
                # 3.2. or add the "false" positive '#' to the output
                end_index = start_index + 1
                output = output + '#'  # we need '#' this time
            # 4. cut input_text from the end position
            input_text = input_text[end_index:]
            # 5. loop
            start_index = input_text.find(start_symbols[i])
        output = output + input_text
        input_text = output
    while output.find('\n\n\n') != -1:
        output = output.replace('\n\n\n', '\n\n')
    return output


def rename_variables(input_text):
    """
    Randomly rename variables in input_text and return the result with a mapping table.
    :param input_text: a string representing a script to work on.
    :return: (string, dict): an input_text with renamed variables, a mapping table
    """
    start_symbol = '$'
    powershell_auto_vars = ['$NestedPromptLevel', '$PSBoundParameters', '$ExecutionContext', '$ConsoleFileName',
                            '$EventSubscriber', '$SourceEventArgs', '$PSDebugContext', '$PsVersionTable',
                            '$PSCommandPath', '$LastExitCode', '$MyInvocation', '$PSScriptRoot', '$PSSenderInfo',
                            '$PsUICulture', '$SourceArgs', '$StackTrace', '$EventArgs', '$PsCulture', '$Allnodes',
                            '$PsCmdlet', '$ForEach', '$Matches', '$Profile', '$ShellID', '$PsHome', '$PSitem',
                            '$Sender', '$Error', '$Event', '$False', '$Input', '$Args', '$Home', '$Host', '$NULL',
                            '$This', '$True', '$OFS', '$PID', '$Pwd', '$$', '$?', '$^', '$_', '$(']

    powershell_system_vars = []
    powershell_system_vars = ['Advapi32', 'AccessMask', 'AppDomain', 'Architecture', 'AssemblyName', 'Assembly',
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
                              'UnmanagedType', 'UserNameToAdd']
    powershell_auto_system_vars = powershell_auto_vars + ['$' + i for i in powershell_system_vars]
    # before obfuscation
    not_to_replace_dict = {}
    for system_var in powershell_system_vars:
        # rand_str = random_string()
        if '$' + system_var.lower() in input_text.lower():
            for es in END_SYMBOLS:
                if '$' + system_var.lower() + es in input_text.lower():
                    # extract children if any
                    # ensure there are no variables to obfuscate that will coincide with powershell_system_vars children.
                    local_found = input_text.lower().find('$' + system_var.lower() + '.')
                    if local_found > -1:
                        local_found += len('$' + system_var.lower() + '.')
                        child = input_text[local_found:
                                                 local_found + min([input_text[local_found:].find(end_symb)
                                                                    for end_symb in END_SYMBOLS
                                                                    if input_text[local_found:].find(end_symb) != -1])]
                        if '$' + child.lower() not in not_to_replace_dict.keys():
                            for end_symbol in END_SYMBOLS_BY_2:
                                if '.' + child.lower() + end_symbol[0] in input_text.lower() and \
                                        '$' + child.lower() + end_symbol[1] in input_text.lower():
                                    if '$' + child.lower() not in not_to_replace_dict.keys():
                                        not_to_replace_dict['$' + child.lower()] = None
                                        break
                    # rename
                    # re_sv = re.compile(re.escape('$' + system_var.lower() + es), re.IGNORECASE)
                    # input_text = re_sv.sub('$' + system_var + '_' + rand_str + es, input_text)
    # OBFUSCATION STARTS
    input_text_raw = input_text
    vars_dict = {}
    output = ''
    # 1. initial search
    start_index = input_text.find(start_symbol)
    start_index_raw = start_index
    end_index = start_index
    while start_index >= 0:
        # 1. append everything up to start_index to the output
        output = output + input_text[:start_index]
        # 2. then, either 2.1, 2.2 or 2.3:
        # " does not cancel $ symbol, ' does.
        # if we're in "here", ' inside "" does not cancel $.
        assert input_text_raw[:start_index_raw][-start_index:] == input_text[:start_index][-start_index:]
        if (input_text_raw[:start_index_raw].count("'") -
            input_text_raw[:start_index_raw].count("`'") -
            input_text_raw[:start_index_raw].count('"\'"')) % 2 != 0 and not\
                (input_text_raw[:start_index_raw].count('"') -
                 input_text_raw[:start_index_raw].count('`"') -
                 input_text_raw[:start_index_raw].count("'\"'")) % 2 != 0:
            # we're in 'here'
            # 2.1.1. add for the "false" positive '$'
            end_index = start_index + 1
            output = output + "$"
        elif input_text[start_index - 1] == "`" or input_text[start_index + 1] in END_SYMBOLS:
            # 2.1.2. add for the "false" positive '$'
            end_index = start_index + 1
            output = output + "$"
        elif any([(input_text[start_index: start_index + len(exc_var)].lower() == exc_var.lower() and
                  input_text[start_index + len(exc_var)] in END_SYMBOLS) for exc_var in powershell_auto_system_vars]):
            for exc_var in powershell_auto_system_vars:
                if input_text[start_index: start_index + len(exc_var)].lower() == exc_var.lower() and \
                        input_text[start_index + len(exc_var)] in END_SYMBOLS:
                    # 2.2. add for the "false" positive '$'
                    end_index = start_index + len(exc_var)
                    output = output + exc_var  # randomize_case(exc_var)
                    break
            # value's guaranteed by elif condition.
        else:
            # 2.3. or find the ending
            end_index = start_index
            end_index = end_index + min([input_text[end_index:].find(end_symbol)
                                         for end_symbol in END_SYMBOLS
                                         if input_text[end_index:].find(end_symbol) != -1])
            # check if the ending was a false positive due to escape symbols:
            # assert input_text_raw[:start_index_raw][-8:] == input_text[:start_index][-8:]
#            while input_text[end_index] == "`" or \
#                    (input_text_raw[:start_index_raw].count("'") -
#                     input_text_raw[:start_index_raw].count("`'") -
#                     input_text_raw[:start_index_raw].count('"\'"')) % 2 != 0 and not \
                    #(input_text_raw[:start_index_raw].count('"') -
                     #input_text_raw[:start_index_raw].count('`"') -
                     #input_text_raw[:start_index_raw].count("'\"'")) % 2 != 0:
                #end_index = end_index + min([input_text[end_index:].find(end_symbol)
                                             #for end_symbol in END_SYMBOLS
                                             #if input_text[end_index:].find(end_symbol) != -1])
            # 3. generate and append a new variable name
            source_var_name = input_text[start_index: end_index]

            res_1 = any([(" -" + source_var_name[1:].lower() + es) in input_text_raw.lower() for es in END_SYMBOLS])
            res_2 = any([("." + source_var_name[1:].lower() + es) in input_text_raw.lower() for es in END_SYMBOLS])
            res_3 = ("['" + source_var_name[1:].lower() + "']") in input_text_raw.lower()
            res_4 = ('["' + source_var_name[1:].lower() + '"]') in input_text_raw.lower()
            res_5 = ('$' + source_var_name[1:].lower() + ':') in input_text_raw.lower()
            if source_var_name.lower() not in not_to_replace_dict and not (res_1 or res_2 or res_3 or res_4 or res_5):
                if source_var_name.lower() not in vars_dict:
                    vars_dict[source_var_name.lower()] = random_string()
                output = output + "$" + vars_dict[source_var_name.lower()]
            else:
                output = output + source_var_name
        # 4. cut input_text from the end position
        input_text = input_text[end_index:]
        offset = end_index - start_index  # if var this is len(source_var_name)
        input_text_raw_cut = input_text_raw[start_index_raw + offset:]
        assert input_text_raw_cut[:-3] == input_text[:-3]
        # 5. loop
        start_index = input_text.find(start_symbol)
        start_index_raw = start_index_raw + offset + start_index
    output = output + input_text
    # 6. additional replacement 1 - function parameter names (FUNCTION_NAME -PARAMETER):
    for end_symbol in END_SYMBOLS:
        if end_symbol != '\\':
            for k, v in vars_dict.items():
                k_ = k[1:]
                re_k = re.compile(re.escape(" -" + k_ + end_symbol), re.IGNORECASE)
                output = re_k.sub(" -" + v + end_symbol, output)
    # 7. additional replacement 2 - attributes (object.attribute):
    for end_symbol in END_SYMBOLS:
        if end_symbol != '\\':
            for k, v in vars_dict.items():
                k_ = k[1:]
                re_k = re.compile(re.escape("." + k_ + end_symbol), re.IGNORECASE)
                output = re_k.sub("." + v + end_symbol, output)
    # 8. additional replacement 3 - parameter names in quotes (GetField('PARAMETER')):
    for k, v in vars_dict.items():
        k_ = k[1:]
        re_k = re.compile(re.escape("'" + k_ + "'"), re.IGNORECASE)
        output = re_k.sub("'" + v + "'", output)
    return output, vars_dict


def main(input_text):
    v_dict, f_dict = {}, {}
    output1 = delete_comments(input_text)
    output2, v_dict = rename_variables(output1)
    return output1, output2, v_dict, f_dict


if __name__ == '__main__':
    old_file = 'PowerUp.ps1 - Source.txt'
    old_file_split = old_file.split('.')
    new_semi_obfs_file = ''.join(old_file_split[:-1]) + ' - semi-obfuscated.' + old_file_split[-1]
    new_obfs_file = ''.join(old_file_split[:-1]) + ' - obfuscated.' + old_file_split[-1]
    with open(old_file, 'r') as fr:
        input_data = fr.read()
    semi_obfs_data, obfs_data, vars_dict, funcs_dict = main(input_data)
    with open(new_semi_obfs_file, 'w') as f:
        f.write(semi_obfs_data)
    with open(new_obfs_file, 'w') as f:
        f.write(obfs_data)
    vd = sorted([' - '.join(i) for i in vars_dict.items()])
    fd = sorted([' - '.join(i) for i in funcs_dict.items()])
    mapping = 'Functions: \n' + '\n'.join(fd) + '\n\n\nVariables: \n' + '\n'.join(vd)
    with open(new_obfs_file + '- name mapping.txt', 'w') as f:
        f.write(str(mapping))
