# ****************************************************************************
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ****************************************************************************

from .hqc_constants import HQC_CODE_LENGTH, HQC_CODE_DIMENSION, HQC_SECRET_KEY_WEIGHT, HQC_ERROR_WEIGHT
from ..base_problem import BaseProblem
from math import log2


class HQCProblem(BaseProblem):
    def __init__(self, n: int, k: int, w: int, w_e: int, **kwargs):
        """Construct an instance of HQCProblem.

        Contains the parameters of the HQC public-key encryption scheme.

        Args:
            n (int): Code length (length of the quasi-cyclic code, also the ring dimension).
            k (int): Code dimension.
            w (int): Hamming weight of the secret key vectors (y and x each have weight w).
            w_e (int): Hamming weight of the error/noise vectors used in encryption.
            **kwargs: Additional keyword arguments.
                memory_bound: Maximum allowed memory to use for solving the problem.

        Examples:
            >>> from cryptographic_estimators.HQCEstimator import HQCProblem
            >>> HQCProblem(n=35338, k=17669, w=132, w_e=75)
            HQC instance with (n, k, w, w_e) = (35338, 17669, 132, 75)
        """
        super().__init__(**kwargs)

        if n < 1:
            raise ValueError("n must be >= 1")
        if k < 1 or k >= n:
            raise ValueError("k must be in the range [1, n-1]")
        if w < 1:
            raise ValueError("w must be >= 1")
        if w_e < 1:
            raise ValueError("w_e must be >= 1")
        if w > n:
            raise ValueError("w must be <= n")
        if w_e > n:
            raise ValueError("w_e must be <= n")

        self.parameters[HQC_CODE_LENGTH] = n
        self.parameters[HQC_CODE_DIMENSION] = k
        self.parameters[HQC_SECRET_KEY_WEIGHT] = w
        self.parameters[HQC_ERROR_WEIGHT] = w_e

    def to_bitcomplexity_time(self, basic_operations: float):
        """Return the bit-complexity corresponding to a certain amount of basic operations.

        Args:
            basic_operations (float): Number of basic operations (logarithmic).
        """
        n = self.parameters[HQC_CODE_LENGTH]
        return basic_operations + log2(n)

    def to_bitcomplexity_memory(self, elements_to_store: float):
        """Return the memory bit-complexity associated to a given number of elements to store.

        Args:
            elements_to_store (float): Number of elements to store (logarithmic).
        """
        n = self.parameters[HQC_CODE_LENGTH]
        return elements_to_store + log2(n)

    def get_parameters(self):
        """Return the problem parameters.

        Returns:
            list: [n, k, w, w_e]
        """
        return list(self.parameters.values())

    def __repr__(self):
        n, k, w, w_e = self.get_parameters()
        return f"HQC instance with (n, k, w, w_e) = ({n}, {k}, {w}, {w_e})"
