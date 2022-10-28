import click
import json
import subprocess
import time

from os import getenv
from os.path import abspath
from os.path import dirname
from os.path import isfile
from os.path import join
import os
import pickle
import networkx as nx



IDA_PATH = getenv("IDA_PATH", "D:/idapro-7.7/ida64")
IDA32_PATH = getenv("IDA32_PATH", "D:/idapro-7.7/ida")
IDA_PLUGIN = join(dirname(abspath(__file__)), 'IDA_graph.py')
REPO_PATH = dirname(dirname(dirname(abspath(__file__))))
LOG_PATH = "IDA_graph_log.txt"


@click.command()
@click.option('-j', '--json-path', required=True,
              help='JSON file with selected functions.')
@click.option('-o', '--output-dir', required=True,
              help='Output directory.')
def main(json_path, output_dir):

    try:
        print("[D] JSON path: {}".format(json_path))
        print("[D] Output directory: {}".format(output_dir))

        if not isfile(json_path):
            print("[!] Error: {} does not exist".format(json_path))
            return

        with open(json_path) as f_in:
            jj = json.load(f_in)

        success_cnt, error_cnt = 0, 0
        start_time = time.time()
        for idb_rel_path in jj.keys():
            print("\n[D] Processing: {}".format(idb_rel_path))

            # Convert the relative path into a full path
            idb_path = join(REPO_PATH, idb_rel_path)
            print("[D] IDB full path: {}".format(idb_path))

            if not isfile(idb_path):
                print("[!] Error: {} does not exist".format(idb_path))
                continue

            # Call the correct version of IDA based on the 32/64 bit version
            ida_path_t = IDA_PATH
            # if idb_path.endswith(".idb"):
            #     ida_path_t = IDA32_PATH

            cmd = [ida_path_t,
                   '-A',
                   '-L{}'.format(LOG_PATH),
                   '-S{}'.format(IDA_PLUGIN),
                   '-Ograph:{};{};{}'.format(
                       json_path,
                       idb_rel_path,
                       output_dir),
                   idb_path]

            print("[D] cmd: {}".format(cmd))

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()

            if proc.returncode == 0:
                print("[D] {}: success".format(idb_path))
                success_cnt += 1
            else:
                print("[!] Error in {} (returncode={})".format(
                    idb_path, proc.returncode))
                error_cnt += 1

        end_time = time.time()
        print("[D] Elapsed time: {}".format(end_time - start_time))
        with open(LOG_PATH, "a+") as f_out:
            f_out.write("elapsed_time: {}\n".format(end_time - start_time))

        print("\n# IDBs correctly processed: {}".format(success_cnt))
        print("# IDBs error: {}".format(error_cnt))

    except Exception as e:
        print("[!] Exception in get_graph\n{}".format(e))


if __name__ == '__main__':
    main()
    # output_path = r"D:\Download\binary\IDBs\Dataset\zlib\Dataset-graph\arm64-clang-O0_minigzipsh_graph.pkl"
    # with open(output_path, 'rb') as f_in:
    #     data = pickle.load(f_in)
    # for func_name in data.keys():
    #     for node in data[func_name].nodes:
    #         print(data[func_name].nodes[node])
    #     break



