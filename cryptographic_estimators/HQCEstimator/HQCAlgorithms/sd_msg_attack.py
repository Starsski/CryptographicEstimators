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
from ...base_constants import BASE_ATTACK_TYPE_MSG_RECOVERY
from ...SDEstimator import SDEstimator
from math import log2
import copy


class SDMsgAttack(HQCAlgorithm):
    def __init__(self, problem: HQCProblem, **kwargs):
        """Construct an instance of SDMsgAttack for HQC.

        Estimates the complexity of a message-recovery (decryption failure /
        ciphertext decoding) attack on HQC.  Recovering the plaintext from a
        ciphertext reduces to solving SD(n=2n, k=n, w=w_e) where w_e is the
        combined weight of the encryption noise vectors (e, r1, r2).

        Args:
            problem (HQCProblem): An HQCProblem instance with parameters (n, k, w, w_e).

        Examples:
            >>> from cryptographic_estimators.HQCEstimator import HQCEstimator
            >>> A = HQCEstimator(n=17669, k=8835, w=66, w_e=76)
            >>> A.table() # doctest: +SKIP
        """
        super().__init__(problem, **kwargs)
        self._name = "SDMsgAttack"
        self._attack_type = BASE_ATTACK_TYPE_MSG_RECOVERY

        n, _, _, w_e = self.problem.get_parameters()
        sd_kwargs = copy.copy(kwargs)
        if "bit_complexities" in sd_kwargs:
            sd_kwargs.pop("bit_complexities")
        # Message recovery: solve SD(2n, n, w_e)
        self._SDEstimator = SDEstimator(
            n=2 * n, k=n, w=w_e,
            nsolutions=0,
            memory_bound=self.problem.memory_bound,
            bit_complexities=0,
            **sd_kwargs,
        )

    def get_fastest_sd_algorithm(self):
        """Return the fastest algorithm found by the internal SDEstimator."""
        return self._SDEstimator.fastest_algorithm()

    def _compute_time_complexity(self, parameters: dict):
        """Return the time complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        n, _, _, _ = self.problem.get_parameters()
        # The adjustment `- log2(n) / 2` accounts for the square-root speedup
        # available via list decoding when the ciphertext has a known structure
        # (quasi-cyclic codes), following the same model as BIKEEstimator's
        # SDMsgAttack.
        return max(
            self.get_fastest_sd_algorithm().time_complexity() - log2(n) / 2,
            self._compute_memory_complexity(parameters),
        )

    def _compute_memory_complexity(self, parameters: dict):
        """Return the memory complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().memory_complexity()

    def _compute_tilde_o_time_complexity(self, parameters: dict):
        """Return the tilde-O time complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().time_complexity()

    def _compute_tilde_o_memory_complexity(self, parameters: dict):
        """Return the tilde-O memory complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_sd_algorithm().memory_complexity()

    def quantum_time_complexity(self):
        """Return the quantum time complexity of the message-recovery attack.

        Applies a Grover-search speedup to the best classical ISD algorithm,
        halving the classical bit-security (subtracting 1 bit from the log2
        complexity).  This is a standard lower-bound approximation widely used
        in the literature (see e.g. Bernstein & Lange, "Post-Quantum
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
