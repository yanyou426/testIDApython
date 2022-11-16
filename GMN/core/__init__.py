# Ignore TF warnings due to numpy version 1.17.2
import warnings
warnings.simplefilter("ignore")

from .config import *
from .gnn_model import *
