import os
import time

import pybluecat
from helper_functions import merge_lists
from test_data import *


def test_search_by_object_types(session, test_dictionary, retries=3, delay=5):
    print('Testing search_by_object_types()')
    search_results = []
    returned_results = []
    for test_item in test_dictionary:
        retry_count = 0
        while retry_count < retries:
            try:
                search_results = session.search_by_object_types(keyword=test_item, obj_type='Server', count=20)
                search_results = [session.entity_to_json(entity=search_result) for search_result in search_results]
                returned_results += search_results
                # print(f'Search results for {test_item}: {search_results}')
                break
            except Exception as e:
                # print(f'Error: {e}')
                retry_count += 1
                time.sleep(delay)
    return returned_results


def test_search_by_category(session, test_dictionary, retries=3, delay=5):
    print('Testing search_by_category()')
    search_results = []
    returned_results = []
    for test_item in test_dictionary:
        retry_count = 0
        while retry_count < retries:
            try:
                search_results = session.search_by_category(keyword=test_item, category='SERVERS', count=20)
                search_results = [
                    session.entity_to_json(entity=search_result) for search_result in search_results
                    if search_result.get('type') == 'Server'
                ]
                returned_results += search_results
                # print(f'Search results for {test_item}: {search_results}')
                break
            except Exception as e:
                # print(f'Error: {e}')
                retry_count += 1
                time.sleep(delay)
    return returned_results


def main():
    bam_host = os.getenv('BLUECAT_HOST')
    bam_user = os.getenv('BLUECAT_USER')
    bam_pass = os.getenv('BLUECAT_PASS')
    bam_cfg = os.getenv('BLUECAT_CFG')
    bam = pybluecat.BAM(bam_host, bam_user, bam_pass, bam_cfg)

    view_object_results = bam.search_by_object_types(keyword='*', obj_type='View', count=20)
    print(f'\nView objects: {view_object_results}')
    for view in view_object_results:
        view_parent = bam.get_parent(entity_id=view['id'])
        print(f'View parent: {view_parent}')

    object_results = test_search_by_object_types(session=bam, test_dictionary=test_search)
    print(f'Object search results:\n{object_results}\n')
    category_results = test_search_by_category(session=bam, test_dictionary=test_search)
    print(f'Category search results:\n{category_results}\n')
    merged_lists = merge_lists(list1=object_results, list2=category_results)
    print(f'Merged results:\n{merged_lists}\n')
    for server in merged_lists:
        print(f'Server [{server["id"]}]: {server["name"]}')


if __name__ == '__main__':
    main()
