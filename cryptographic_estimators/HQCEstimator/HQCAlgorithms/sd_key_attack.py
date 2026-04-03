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

from ..hqc_algorithm import HQCAlgorithm
from ..hqc_problem import HQCProblem
from ...base_constants import BASE_ATTACK_TYPE_KEY_RECOVERY
from ...SDEstimator import SDEstimator
from math import log2
import copy


class SDKeyAttack(HQCAlgorithm):
    def __init__(self, problem: HQCProblem, **kwargs):
        """Construct an instance of SDKeyAttack for HQC.

        Estimates the complexity of a key-recovery attack on HQC by reducing it
        to a binary Syndrome Decoding (SD) instance.  The public key of HQC is a
        quasi-cyclic code of length 2n and dimension n; recovering the secret key
        (x, y) of combined weight w reduces to solving SD(n=2n, k=n, w=w).

        Args:
            problem (HQCProblem): An HQCProblem instance with parameters (n, k, w, w_e).

        Examples:
            >>> from cryptographic_estimators.HQCEstimator import HQCEstimator
            >>> A = HQCEstimator(n=17669, k=8835, w=66, w_e=76)
            >>> A.table() # doctest: +SKIP
        """
        super().__init__(problem, **kwargs)
        self._name = "SDKeyAttack"
        self._attack_type = BASE_ATTACK_TYPE_KEY_RECOVERY

        n, _, w, _ = self.problem.get_parameters()
        sd_kwargs = copy.copy(kwargs)
        if "bit_complexities" in sd_kwargs:
            sd_kwargs.pop("bit_complexities")
        # Key recovery: solve SD(2n, n, w) — the combined weight of (x, y) is w
        self._SDEstimator = SDEstimator(
            n=2 * n, k=n, w=w,
            nsolutions=log2(n),
            memory_bound=self.problem.memory_bound,
            bit_complexities=0,
            **sd_kwargs,
        )

    def get_fastest_sd_algorithm(self):
        """Return the fastest algorithm found by the internal SDEstimator."""
        return self._SDEstimator.fastest_algorithm()

    def _compute_time_complexity(self, parameters: dict):
        """Return the time complexity of the key-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().time_complexity()

    def _compute_memory_complexity(self, parameters: dict):
        """Return the memory complexity of the key-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().memory_complexity()

    def _compute_tilde_o_time_complexity(self, parameters: dict):
        """Return the tilde-O time complexity of the key-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().time_complexity()

    def _compute_tilde_o_memory_complexity(self, parameters: dict):
        """Return the tilde-O memory complexity of the key-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().memory_complexity()

    def quantum_time_complexity(self):
        """Return the quantum time complexity of the key-recovery attack.

        Applies a Grover-search speedup to the best classical ISD algorithm,
        halving the classical bit-security (i.e. subtracting 1 bit from the
        log2 complexity).  This is a standard lower-bound approximation widely
        used in the literature (see e.g. Bernstein & Lange, "Post-Quantum
        Cryptography", 2017).

        Returns:
            float: log2 of the quantum gate complexity.
        """
        classical = self._compute_time_complexity({})
        return classical / 2

    def get_optimal_parameters_dict(self):
        """Return the optimal parameters of the internally used SD algorithm."""
        params = self.get_fastest_sd_algorithm().get_optimal_parameters_dict()
        params["SD-algorithm"] = self.get_fastest_sd_algorithm()._name
        return params

    def reset(self):
        """Reset to the initial state."""
        super().reset()
        self._SDEstimator.reset()
