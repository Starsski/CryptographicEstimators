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

from ..base_algorithm import BaseAlgorithm
from .hqc_problem import HQCProblem


class HQCAlgorithm(BaseAlgorithm):
    def __init__(self, problem: HQCProblem, **kwargs):
        """Base class for HQC algorithm complexity estimators.

        Args:
            problem (HQCProblem): An HQCProblem instance with all necessary parameters.
        """
        super(HQCAlgorithm, self).__init__(problem, **kwargs)
        self._name = "BaseHQCAlgorithm"

    def __repr__(self):
        n, k, w, w_e = self.problem.get_parameters()
        return (
            f"{self._name} estimator for the HQC scheme "
            f"with parameters (n, k, w, w_e) = ({n}, {k}, {w}, {w_e})"
        )
