"""
Helper functions for unit tests
"""


def sort_and_filter_list_of_dicts(list_of_dicts, unique_key):
    sorted_list = sorted(list_of_dicts, key=lambda x: x[unique_key])
    unique_entries = []
    unique_keys = set()

    for entry in sorted_list:
        key_value = entry[unique_key]
        if key_value not in unique_keys:
            unique_entries.append(entry)
            unique_keys.add(key_value)

    return unique_entries


def merge_lists(list1, list2):
    merged_list = []

    # Create a dictionary to store the items based on 'id'
    dict_by_id = {}

    # Add items from list1 to the dictionary
    for item in list1:
        dict_by_id[item['id']] = item

    # Update or add items from list2 to the dictionary
    for item in list2:
        dict_by_id[item['id']] = item

    # Convert the dictionary values back to a list
    merged_list = list(dict_by_id.values())

    return merged_list
