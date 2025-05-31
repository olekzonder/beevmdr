import re
from typing import List, Tuple
from database_worker import DatabaseManager

class CVEMatcher:
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    def extract_keywords(self, description: str) -> List[str]:
        patterns = [
            r'\b(\w+\.(exe|dll|so|py|js|jar))\b',
            r'\b(Apache|Nginx|WordPress|OpenSSL|Tomcat)\b',
            r'\b(\w+-\w+)\b'
        ]
        
        keywords = set()
        for pattern in patterns:
            matches = re.findall(pattern, description, re.IGNORECASE)
            for match in matches:
                keyword = match[0] if isinstance(match, tuple) else match
                if len(keyword) > 3:
                    keywords.add(keyword.lower())
        
        return sorted(keywords)[:10]  # Сортируем для стабильности тестов
    
    def match_cves_with_events(self, cve_data: List[Tuple[str, str, float]]) -> List[Dict]:
        results = []
        for cve_id, description, cvss in cve_data:
            keywords = self.extract_keywords(description)
            if not keywords:
                continue
                
            events = self.db.find_events_by_keywords(keywords)
            if events:
                results.append({
                    'cve_id': cve_id,
                    'cvss_score': cvss,
                    'description': description,
                    'matched_events': events
                })
        
        return results
