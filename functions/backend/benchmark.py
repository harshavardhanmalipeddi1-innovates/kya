# Research benchmark framework
import time
from typing import Dict, Any, List, Callable

class BenchmarkSuite:
    def __init__(self): self._results = []
    def measure_latency(self, name, fn, iterations=100):
        latencies = []
        for _ in range(iterations):
            start = time.time()
            fn()
            latencies.append(time.time() - start)
        latencies.sort()
        n = len(latencies)
        result = {"benchmark": name, "iterations": iterations, "latency_ms": {
            "mean": round(sum(latencies)/n*1000, 2),
            "p50": round(latencies[n//2]*1000, 2),
            "p95": round(latencies[int(n*0.95)]*1000, 2),
        }}
        self._results.append(result)
        return result
    def accuracy_metrics(self, predictions, labels):
        tp=fp=fn=tn=0
        for p,l in zip(predictions, labels):
            if p!="APPROVE" and l!="APPROVE": tp+=1
            elif p!="APPROVE" and l=="APPROVE": fp+=1
            elif p=="APPROVE" and l!="APPROVE": fn+=1
            else: tn+=1
        precision = tp/(tp+fp) if (tp+fp)>0 else 0
        recall = tp/(tp+fn) if (tp+fn)>0 else 0
        f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0
        return {"tp":tp,"fp":fp,"fn":fn,"tn":tn,"precision":round(precision,4),"recall":round(recall,4),"f1":round(f1,4)}
    def get_results(self): return self._results
