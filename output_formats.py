# output_formats.py

import json
from datetime import datetime
from typing import List, Dict, Any, Optional

def json_output(
    results: List[Dict[str, Any]],
    timestamp: datetime,
    simulation_info: Optional[str] = None,
) -> str:
    """
    Return a JSON string for inverter results.
    This remains intentionally thin and pure.
    """
    data = {
        "results": results,
        "timestamp": timestamp.isoformat(),
    }
    if simulation_info:
        data["simulation"] = simulation_info
    return json.dumps(data, indent=2, default=str)
