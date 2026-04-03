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

from ..rqc_algorithm import RQCAlgorithm
from ..rqc_problem import RQCProblem
from ...base_constants import BASE_ATTACK_TYPE_MSG_RECOVERY
from ...RankSDEstimator import RankSDEstimator
import copy


class RankSDMsgAttack(RQCAlgorithm):
    def __init__(self, problem: RQCProblem, **kwargs):
        """Construct an instance of RankSDMsgAttack for RQC.

        Estimates the complexity of a message-recovery attack on RQC by reducing
        it to a Rank Syndrome Decoding (RSD) instance.  Recovering the plaintext
        from a ciphertext reduces to solving RSD(q, m, n=2n, k=n, r=w_e) where
        w_e is the rank weight of the encryption noise.

        Args:
            problem (RQCProblem): An RQCProblem instance with parameters (q, m, n, k, w, w_e).

        Examples:
            >>> from cryptographic_estimators.RQCEstimator import RQCEstimator
            >>> A = RQCEstimator(q=2, m=31, n=33, k=15, w=10, w_e=6)
            >>> A.table() # doctest: +SKIP
        """
        super().__init__(problem, **kwargs)
        self._name = "RankSDMsgAttack"
        self._attack_type = BASE_ATTACK_TYPE_MSG_RECOVERY

        q, m, n, _, _, w_e = self.problem.get_parameters()
        rsd_kwargs = copy.copy(kwargs)
        if "bit_complexities" in rsd_kwargs:
            rsd_kwargs.pop("bit_complexities")
        # Message recovery: solve RSD(q, m, 2n, n, w_e)
        self._RankSDEstimator = RankSDEstimator(
            q=q, m=m, n=2 * n, k=n, r=w_e,
            memory_bound=self.problem.memory_bound,
            bit_complexities=0,
            **rsd_kwargs,
        )

    def get_fastest_ranksd_algorithm(self):
        """Return the fastest algorithm found by the internal RankSDEstimator."""
        return self._RankSDEstimator.fastest_algorithm()

    def _compute_time_complexity(self, parameters: dict):
        """Return the time complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_ranksd_algorithm().time_complexity()

    def _compute_memory_complexity(self, parameters: dict):
        """Return the memory complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_ranksd_algorithm().memory_complexity()

    def _compute_tilde_o_time_complexity(self, parameters: dict):
        """Return the tilde-O time complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_ranksd_algorithm().time_complexity()

    def _compute_tilde_o_memory_complexity(self, parameters: dict):
        """Return the tilde-O memory complexity of the message-recovery attack.

        Args:
            parameters (dict): Dictionary of algorithm parameters (unused here).
        """
        return self.get_fastest_ranksd_algorithm().memory_complexity()

    def quantum_time_complexity(self):
        """Return the quantum time complexity of the message-recovery attack.

        Applies a Grover-search speedup to the best classical rank-metric ISD
        algorithm, halving the classical bit-security (subtracting 1 bit from
        the log2 complexity).  This is a standard lower-bound approximation;
        see also Naya-Plasencia et al. on quantum attacks in the rank metric.

        Returns:
            float: log2 of the quantum gate complexity.
        """
        classical = self._compute_time_complexity({})
        return classical / 2

    def get_optimal_parameters_dict(self):
        """Return the optimal parameters of the internally used RankSD algorithm."""
        params = self.get_fastest_ranksd_algorithm().get_optimal_parameters_dict()
        params["RankSD-algorithm"] = self.get_fastest_ranksd_algorithm()._name
        return params

    def reset(self):
        """Reset to the initial state."""
        super().reset()
        self._RankSDEstimator.reset()
