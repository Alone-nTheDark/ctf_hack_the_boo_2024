from collections import OrderedDict
import os
import Evtx.Evtx as evtx

def process_evtx_files(folder):
    for filename in os.listdir(folder):
        if filename.endswith('.evtx'):
            evtx_path = os.path.join(folder, filename)
            print(f"Processing {evtx_path}...")
            for id, data in enumerate(get_events(evtx_path)):
                print(data)

def get_events(input_file):
    with evtx.Evtx(input_file) as event_log:
        for record in event_log.records():
            yield record.xml()

def main():
    process_evtx_files('.')

if __name__ == "__main__":
    main()
