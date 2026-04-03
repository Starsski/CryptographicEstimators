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

from .rqc_algorithm import RQCAlgorithm
from .rqc_problem import RQCProblem
from ..base_estimator import BaseEstimator
from math import inf
import warnings

warnings.filterwarnings("ignore", category=RuntimeWarning)


class RQCEstimator(BaseEstimator):
    """Estimator for the classical and quantum security of the RQC scheme.

    RQC (Rank Quasi-Cyclic) is a code-based public-key encryption scheme based
    on the hardness of decoding quasi-cyclic codes in the **rank** metric.
    Security reduces to solving Rank Syndrome Decoding (RSD) instances.

    Two attack types are modelled:

    * **RankSDKeyAttack** – recovers the secret key by solving
      RSD(q, m, n=2n, k=n, r=w).
    * **RankSDMsgAttack** – recovers the plaintext by solving
      RSD(q, m, n=2n, k=n, r=w_e).
    """

    excluded_algorithms_by_default = []

    def __init__(self, q: int, m: int, n: int, k: int, w: int, w_e: int,
                 memory_bound=inf, **kwargs):
        """Construct an RQCEstimator instance.

        Args:
            q (int): Base field order (must be a prime power).
            m (int): Extension degree (the ambient field is F_{q^m}).
            n (int): Code length.
            k (int): Code dimension.
            w (int): Rank weight of the secret key vectors.
            w_e (int): Rank weight of the error/noise vectors.
            memory_bound (float): Maximum allowed memory (log2 of bits). Defaults to inf.
            **kwargs: Additional keyword arguments forwarded to the base class and algorithms.
                excluded_algorithms (list): Algorithms to exclude from the estimation.
                theta (float): Exponent for the field-operation cost model (default: 2).

        Examples:
            >>> from cryptographic_estimators.RQCEstimator import RQCEstimator
            >>> A = RQCEstimator(q=2, m=31, n=33, k=15, w=10, w_e=6)
            >>> A.table()
            +-----------------+------------------+----------------+
            |                 |                  |    estimate    |
            +-----------------+------------------+-------+--------+
            | algorithm       |   attack_type    |  time | memory |
            +-----------------+------------------+-------+--------+
            | RankSDKeyAttack |   key-recovery   | 159.0 |   19.9 |
            | RankSDMsgAttack | message-recovery |  95.0 |   19.9 |
            +-----------------+------------------+-------+--------+
        """
        super(RQCEstimator, self).__init__(
            RQCAlgorithm,
            RQCProblem(q=q, m=m, n=n, k=k, w=w, w_e=w_e, memory_bound=memory_bound, **kwargs),
            **kwargs,
        )
        self._estimator_type = "scheme"

    def table(self, show_quantum_complexity=0, show_tilde_o_time=0,
              show_all_parameters=0, precision=1, truncate=0, *args, **kwargs):
        """Print table describing the complexity of each algorithm and its optimal parameters.

        Args:
            show_quantum_complexity (int): Show quantum time complexity (default: 0).
            show_tilde_o_time (int): Show Ō time complexity (default: 0).
            show_all_parameters (int): Show all optimization parameters (default: 0).
            precision (int): Number of decimal digits output (default: 1).
            truncate (int): Truncate rather than round the output (default: 0).

        Examples:
            >>> from cryptographic_estimators.RQCEstimator import RQCEstimator
            >>> A = RQCEstimator(q=2, m=31, n=33, k=15, w=10, w_e=6)
            >>> A.table()
            +-----------------+------------------+----------------+
            |                 |                  |    estimate    |
            +-----------------+------------------+-------+--------+
            | algorithm       |   attack_type    |  time | memory |
            +-----------------+------------------+-------+--------+
            | RankSDKeyAttack |   key-recovery   | 159.0 |   19.9 |
            | RankSDMsgAttack | message-recovery |  95.0 |   19.9 |
            +-----------------+------------------+-------+--------+
        """
        super(RQCEstimator, self).table(
            show_quantum_complexity=show_quantum_complexity,
            show_tilde_o_time=show_tilde_o_time,
            show_all_parameters=show_all_parameters,
            precision=precision,
            truncate=truncate,
            *args,
            **kwargs,
        )
