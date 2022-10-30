# Preprocessing of dataset

## BoW.ipynb

Use `Tokenizer` to count the opcode appearing in the library as the feature vector of the node in the graph.

Currently, BoW opcode 200 is used as the standard.

The part of generating graph is updated in `../IDA_graph`.


## test_pkl.ipynb

Add some extra information of a node to the graph struction and save a dict using function_name as key.

## utils.py

Some basic function for graph matching.

## GraphSimilarityDataset.py

Class for GraphEditDistanceDataset, mainly from exsiting implementation code.

## BinaryFunctionSimilarityDataset.py

Class for BinarySimilarityDataset, mainly for self-constructed graph datasets.

Still with bugs, debugging...

