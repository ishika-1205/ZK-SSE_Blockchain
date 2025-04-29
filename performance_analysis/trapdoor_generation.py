# File: performance_analysis/trapdoor_generation.py
import numpy as np
import matplotlib.pyplot as plt
from zk_sse_crypto import ZKSSECrypto
import time

class TrapdoorGenerationAnalysis:
    """
    Measures and analyzes the performance of trapdoor generation 
    for searchable symmetric encryption (SSE).
    """

    def __init__(self):
        self.crypto = ZKSSECrypto()

    def measure_trapdoor_time(self, num_keywords=10):
        """
        Measures the time taken to generate trapdoor keys for a given number of keywords.
        """
        device_id = "iot_device_123"
        sp_id = "ServiceProviderXYZ"

        trapdoor_key = self.crypto.generate_trapdoor_key(device_id, sp_id)
        keywords = [f"keyword_{i}" for i in range(num_keywords)]
        
        start_time = time.time()
        self.crypto.create_searchable_index(keywords, trapdoor_key.hex())
        end_time = time.time()

        return (end_time - start_time) * 1000  # Convert to milliseconds

    def generate_performance_graph(self):
        """
        Plots trapdoor generation time against the number of keywords.
        """
        keyword_counts = np.array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
        trapdoor_times = np.array([self.measure_trapdoor_time(n) for n in keyword_counts])

        plt.figure(figsize=(8, 5))
        plt.plot(keyword_counts, trapdoor_times, marker='o', linestyle='-', label="Trapdoor Generation Time")
        plt.xlabel("Number of Keywords")
        plt.ylabel("Trapdoor Generation Time (ms)")
        plt.title("Trapdoor Generation Time vs. Number of Keywords")
        plt.legend()
        plt.grid(True)
        plt.show()


if __name__ == "__main__":
    analyzer = TrapdoorGenerationAnalysis()
    analyzer.generate_performance_graph()
