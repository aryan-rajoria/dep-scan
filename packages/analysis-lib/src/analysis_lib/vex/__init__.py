"""CSAF VEX document generation.

A typed, layered implementation that turns a dep-scan VDR result plus its
reachability data into an OASIS CSAF VEX document (CSAF 2.1 by default, 2.0
optional). Importing this package only loads the lightweight typed models and
product-tree builder; IO and schema validation live in
:mod:`analysis_lib.vex.emit`.
"""
