# Some use of IDApython


## Requirements

1. Set IDAPro environment:
```bash
export IDA_PATH=D:/idapro-7.7/ida64
```

2. Prepare the python3 environment


## Generate the idb database

Use the [get_idb.py](get_idb.py) to export the IDBs for the binaries of each dataset:
- **Input**: the flag corresponding to the dataset to process (`--db`)
- **Output**: the corresponding IDBs and a log file (`generate_idbs_log.txt`)

Example: generate the IDBs for the Dataset
```bash
python get_idb.py --db
```

## The IDA Pro Plugins

### IDA FlowChart
It extracts basic information from each function with at least five basic blocks.

- **Input**: the folder with the IDBs (`-i`) and the name of the CSV file in output (`-o`).
- **Output**: one CSV file with all the functions with at least five basic blocks.

Also create a python script to generate a_selected_Dataset.json file from flowchart of IDBs.

Example: run the plugin over the IDBs of **zlib** in Dataset
```bash
cd IDA_flowchart
python get_flowchart.py -i D:/Download/binary/IDBs/Dataset/zlib -o aflowchart_Dataset.csv
cd path/to/aflowchart_Dataset.csv
python fc2json.py
```

---

### IDA ACFG-disasm
It creates an ACFG with the basic-blocks disassembly for each selected function.

- **Input**: a JSON file with the selected functions (`-j`) and the name of a folder in output (`-o`).
- **Output**: one JSON file per IDB.

**Note**: the path of the IDB files in the JSON in input **must be Absolute Path** otherwise throwing a FileNotFoundError. 

Example: run the plugin over the functions selected for the zlib in Dataset
```bash
cd IDA_acfg_disasm
python get_acfg_disasm.py -j D:/Download/binary/IDBs/Dataset/zlib/a_selected_Dataset.json -o acfg_disasm_Dataset
```
---

### IDA ACFG-features
It creates an ACFG with the Genius/Gemini features for each selected function.

- **Input**: a JSON file with the selected functions (`-j`) and the name of a folder in output (`-o`).
- **Output**: one JSON file per IDB.


**Note**: the path of the IDB files in the JSON in input **must be Absolute Path** otherwise throwing a FileNotFoundError. 

Example: run the plugin over the functions selected for the zlib in Dataset

```bash
cd IDA_acfg_features
python get_acfg_features.py -j D:/Download/binary/IDBs/Dataset/zlib/a_selected_Dataset.json -o acfg_features_Dataset
```

---

