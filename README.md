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

## The usage of IDA Pro Plugins

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

### IDA  plugin for codeCMR

- **Input**: a JSON file with the selected functions (`-j`) and the name of a folder in output (`-o`).
- **Output**: one JSON file per IDB.

Example: run the plugin over the functions selected for the training set in Dataset

```bash
cd IDA_codeCMR
python get_CMR.py -j D:/Download/binary/IDBs/Dataset/test.json -o D:/Download/binary/IDBs/Dataset
```



## Detailed description

### flowchart

This will generate some basic information of every function for each .idb file.

```python
info = [idb_path, # path of .idb file
		fva, # function virtual address
		func_name, # function name 
        func.start_ea, # start address
        func.end_ea, # end address
        len(bb_list), # length of basic block in this function, should be more than 5
        [bb_list], # list of basic block, each given an address
        hashopcodes(fva)] # extract opcodes of every bb via idaapi.ua_mnem, thus generating the sha256 hash of this function
```

Therefore, each idb will get several function information, prepared for the downstream analysis.

### disasm

It disassembles each function and extract CFG to JSON file.

For each function of each idb file, it will generate:

```python
func_dict = {'nodes': list(nodes_set), # bb address
             'edges': list(edges_set), # bb address pairs, pointing from bb to its successor bb
             'elapsed_time': elapsed_time,
             'basic_blocks': bbs_dict} # information of each bb

bbs_dict[bb.va] = {'bb_len': bb.size,
                   'b64_bytes': b64_bytes, # encoded via base64
                   'bb_heads': bb_heads, # a list() for each instruction in the bb
                   'bb_mnems': bb_mnems, # a list() for all the mnemonics
                   'bb_disasm': bb_disasm, # a list() for the disasms 
                   'bb_norm': bb_norm} # a list() for the normalized disasms

# an example of bb dict is shown as below
{"2166112": {"bb_len": 28, "b64_bytes": "/Xu+qfwLAPn9AwCR/xNA0f+DANGggx/4oQMf+A==", "bb_heads": [2166112, 2166116, 2166120, 2166124, 2166128, 2166132, 2166136], "bb_mnems": ["stp", "str", "mov", "sub", "sub", "stur", "stur"], "bb_disasm": ["stp x29, x30, [sp, #-0x20]!", "str x28, [sp, #0x10]", "mov x29, sp", "sub sp, sp, #4, lsl #12", "sub sp, sp, #0x20", "stur x0, [x29, #-8]", "stur x1, [x29, #-0x10]"], "bb_norm": ["stp_x29,_x30,_[sp-32]", "str_x28,_[sp+16]", "mov_x29,_sp", "sub_sp,_sp,_0x4", "sub_sp,_sp,_0x20", "stur_x0,_[x29-8]", "stur_x1,_[x29-16]"]},
```

### features

It will extract the features from each function and save results to JSON, prepared for Gemini or Genius model.

```python
func_dict = {'nodes': list(nodes_set), # bb address
             'edges': list(edges_set), # bb address pairs, pointing from bb to its successor bb
             'elapsed_time': elapsed_time,
             'basic_blocks': bbs_dict, # information of each bb
 			 'features': function_features
            } 

function_features = {
        'n_func_calls': f_sum(bbs_dict, 'n_call_instrs'), # no. of call
        'n_logic_instrs': f_sum(bbs_dict, 'n_logic_instrs'), # no. of logic
        'n_redirections': f_sum(bbs_dict, 'n_redirect_instrs'), # no. of call, conditional and unconditional
        'n_transfer_instrs': f_sum(bbs_dict, 'n_transfer_instrs'), # no. of transfer
        'size_local_variables': get_size_local_vars(fva), # the size of local variables
        'n_bb': len(bbs_dict),
        'n_edges': len_edges,
        'n_incoming_calls': get_func_incoming_calls(fva), # no. of xrefs
        'n_instructions': f_sum(bbs_dict, 'n_instructions') # no. of mnens
    }

```

### graph for codeCMR

It will generate a networkx graph for each idb , where key is the function name in each idb file.

```python
G, cfunc = parse_func(pfn, strlist)
func_name = idaapi.get_func_name(fva)
G.graph['arch'] = arch
G.graph['name'] = func_name
G.graph['file'] = idb_path
G.graph['pseudocode'] = str(cfunc)
features_dict[func_name] = G
```

The graph info got by `parse_func` includes：

