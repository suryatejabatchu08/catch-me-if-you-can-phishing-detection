"""
Lookalike Domain Detection Engine
Detects typosquatting, homoglyphs, and brand impersonation
"""
try:
    from Levenshtein import distance as lev_distance, ratio as lev_ratio
except ImportError:
    try:
        import Levenshtein as Lev
        lev_distance = Lev.distance
        lev_ratio = Lev.ratio
    except ImportError:
        # Fallback implementation
        def lev_distance(s1, s2):
            if len(s1) < len(s2):
                return lev_distance(s2, s1)
            if len(s2) == 0:
                return len(s1)
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]
        
        def lev_ratio(s1, s2):
            distance = lev_distance(s1, s2)
            max_len = max(len(s1), len(s2))
            return (max_len - distance) / max_len if max_len > 0 else 1.0

from typing import Dict, List, Optional, Tuple, Any
import tldextract
import logging

logger = logging.getLogger(__name__)


class LookalikeDomainDetector:
    """Detect lookalike/typosquatting domains"""
    
    def __init__(self):
        # Top 500+ brand domains by category
        self.brand_whitelist = self._load_brand_whitelist()
        
        # Common homoglyph substitutions
        self.homoglyphs = {
            'a': ['а', 'ạ', 'ă', 'ą'],  # Cyrillic a, various a variants
            'e': ['е', 'ė', 'ę', 'ế'],  # Cyrillic e, variants
            'i': ['і', 'ı', 'l', '1', '!'],  # Cyrillic i, Turkish i, l, 1
            'o': ['о', 'ο', '0', 'ö', 'ø'],  # Cyrillic o, Greek o, zero
            'p': ['р', 'ρ'],  # Cyrillic r, Greek rho
            'c': ['с', 'ϲ'],  # Cyrillic s, Greek lunate sigma
            'y': ['у', 'ỳ', 'ý'],  # Cyrillic y, variants
            'x': ['х', 'χ'],  # Cyrillic kh, Greek chi
            'b': ['ь', 'ḃ'],  # Cyrillic soft sign, variants
            'h': ['һ', 'ḣ'],  # Cyrillic shha, variants
            'n': ['п', 'ո'],  # Cyrillic pe, Armenian
            'm': ['т', 'ṁ'],  # Cyrillic te (looks like m), variants
            's': ['ѕ', 'ṡ'],  # Cyrillic dze, variants
            'g': ['ɡ', 'ġ'],  # Latin small g, variants
            'l': ['1', 'I', 'і', '|'],  # One, capital I, Cyrillic i, pipe
        }
        
        self.similarity_threshold = 0.85  # 85% similarity = suspicious
    
    def _load_brand_whitelist(self) -> Dict[str, List[str]]:
        """Load whitelist of 500+ popular brand domains"""
        return {
            # Financial (50+)
            'financial': [
                'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
                'capitalone.com', 'citi.com', 'usbank.com', 'barclays.com',
                'hsbc.com', 'americanexpress.com', 'discover.com', 'ally.com',
                'goldmansachs.com', 'morganstanley.com', 'schwab.com', 'fidelity.com',
                'vanguard.com', 'etrade.com', 'tdameritrade.com', 'robinhood.com',
                'coinbase.com', 'binance.com', 'kraken.com', 'gemini.com',
                'stripe.com', 'square.com', 'venmo.com', 'cashapp.com',
                'transferwise.com', 'revolut.com', 'monzo.com', 'n26.com',
                'santander.com', 'bbva.com', 'bnpparibas.com', 'dbs.com',
                'standardchartered.com', 'rbs.com', 'lloydsbank.com', 'nationwide.com',
                'pnc.com', 'truist.com', 'regions.com', 'suntrust.com',
                'navyfederal.com', 'usaa.com', 'keybank.com', 'bbt.com',
                'fifth-third.com', 'citizensbank.com'
            ],
            
            # Tech Giants (50+)
            'tech': [
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                'facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com',
                'twitter.com', 'x.com', 'linkedin.com', 'youtube.com',
                'netflix.com', 'spotify.com', 'adobe.com', 'salesforce.com',
                'oracle.com', 'ibm.com', 'sap.com', 'cisco.com',
                'intel.com', 'nvidia.com', 'amd.com', 'dell.com',
                'hp.com', 'lenovo.com', 'asus.com', 'samsung.com',
                'sony.com', 'lg.com', 'panasonic.com', 'toshiba.com',
                'alibaba.com', 'tencent.com', 'baidu.com', 'jd.com',
                'zoom.com', 'slack.com', 'dropbox.com', 'box.com',
                'github.com', 'gitlab.com', 'bitbucket.com', 'atlassian.com',
                'asana.com', 'trello.com', 'notion.com', 'monday.com',
                'shopify.com', 'squarespace.com', 'wix.com', 'wordpress.com'
            ],
            
            # Email & Communication (30+)
            'email': [
                'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
                'icloud.com', 'aol.com', 'hotmail.com', 'live.com',
                'mail.com', 'zoho.com', 'yandex.com', 'gmx.com',
                'tutanota.com', 'fastmail.com', 'hushmail.com', 'runbox.com',
                'mailbox.org', 'posteo.de', 'mailfence.com', 'startmail.com',
                'telegram.com', 'signal.org', 'discord.com', 'skype.com',
                'viber.com', 'line.me', 'wechat.com', 'kakao.com',
                'messenger.com', 'snapchat.com'
            ],
            
            # E-commerce (40+)
            'ecommerce': [
                'amazon.com', 'ebay.com', 'walmart.com', 'target.com',
                'bestbuy.com', 'homedepot.com', 'lowes.com', 'costco.com',
                'macys.com', 'nordstrom.com', 'kohls.com', 'jcpenney.com',
                'alibaba.com', 'aliexpress.com', 'etsy.com', 'wayfair.com',
                'overstock.com', 'newegg.com', 'zappos.com', 'chewy.com',
                'instacart.com', 'doordash.com', 'ubereats.com', 'grubhub.com',
                'postmates.com', 'seamless.com', 'deliveroo.com', 'just-eat.com',
                'booking.com', 'expedia.com', 'airbnb.com', 'hotels.com',
                'trivago.com', 'kayak.com', 'priceline.com', 'orbitz.com',
                'travelocity.com', 'hotwire.com', 'tripadvisor.com', 'vrbo.com'
            ],
            
            # Social Media (25+)
            'social': [
                'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
                'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com',
                'tumblr.com', 'flickr.com', 'medium.com', 'quora.com',
                'stackoverflow.com', 'behance.net', 'dribbble.com', 'vimeo.com',
                'twitch.tv', 'dailymotion.com', 'soundcloud.com', 'mixcloud.com',
                'mastodon.social', 'threads.net', 'bluesky.social', 'truthsocial.com',
                'parler.com'
            ],
            
            # Enterprise & SaaS (40+)
            'enterprise': [
                'salesforce.com', 'microsoft.com', 'office365.com', 'office.com',
                'google.com', 'workspace.google.com', 'aws.amazon.com', 'azure.com',
                'cloud.google.com', 'ibm.com', 'oracle.com', 'sap.com',
                'servicenow.com', 'workday.com', 'adp.com', 'paychex.com',
                'zendesk.com', 'freshworks.com', 'hubspot.com', 'mailchimp.com',
                'constantcontact.com', 'sendgrid.com', 'twilio.com', 'vonage.com',
                'ringcentral.com', 'goto.com', 'webex.com', 'teams.microsoft.com',
                'docusign.com', 'adobesign.com', 'hellosign.com', 'pandadoc.com',
                'jira.atlassian.com', 'confluence.atlassian.com', 'monday.com', 'asana.com',
                'basecamp.com', 'smartsheet.com', 'airtable.com', 'clickup.com'
            ],
            
            # Government & Official (30+)
            'government': [
                'usa.gov', 'irs.gov', 'usps.com', 'usps.gov',
                'ssa.gov', 'fbi.gov', 'dhs.gov', 'state.gov',
                'nasa.gov', 'cdc.gov', 'nih.gov', 'fda.gov',
                'epa.gov', 'sec.gov', 'ftc.gov', 'dol.gov',
                'va.gov', 'medicare.gov', 'socialsecurity.gov', 'dmv.org',
                'gov.uk', 'nhs.uk', 'gov.au', 'gov.ca',
                'europa.eu', 'un.org', 'who.int', 'worldbank.org',
                'imf.org', 'nato.int'
            ],
            
            # Education (30+)
            'education': [
                'edu', 'harvard.edu', 'mit.edu', 'stanford.edu',
                'berkeley.edu', 'yale.edu', 'princeton.edu', 'columbia.edu',
                'upenn.edu', 'cornell.edu', 'caltech.edu', 'northwestern.edu',
                'duke.edu', 'brown.edu', 'dartmouth.edu', 'vanderbilt.edu',
                'rice.edu', 'notredame.edu', 'georgetown.edu', 'cmu.edu',
                'usc.edu', 'ucla.edu', 'ucsd.edu', 'ucsb.edu',
                'ox.ac.uk', 'cam.ac.uk', 'imperial.ac.uk', 'ucl.ac.uk',
                'coursera.org', 'udemy.com', 'khanacademy.org', 'edx.org'
            ],
            
            # Streaming & Entertainment (25+)
            'streaming': [
                'netflix.com', 'hulu.com', 'disneyplus.com', 'hbomax.com',
                'primevideo.com', 'youtube.com', 'twitch.tv', 'vimeo.com',
                'spotify.com', 'applemusic.com', 'pandora.com', 'soundcloud.com',
                'tidal.com', 'deezer.com', 'amazonmusic.com', 'youtubemusic.com',
                'peacocktv.com', 'paramountplus.com', 'showtime.com', 'starz.com',
                'espn.com', 'nfl.com', 'nba.com', 'mlb.com', 'sling.com'
            ],
            
            # Gaming (25+)
            'gaming': [
                'steam.com', 'epicgames.com', 'origin.com', 'ubisoft.com',
                'ea.com', 'activision.com', 'blizzard.com', 'riotgames.com',
                'playstation.com', 'xbox.com', 'nintendo.com', 'nintendo.co.jp',
                'twitch.tv', 'discord.com', 'roblox.com', 'minecraft.net',
                'fortnite.com', 'leagueoflegends.com', 'valorant.com', 'overwatch.com',
                'callofduty.com', 'battlefield.com', 'gog.com', 'humblebundle.com',
                'itch.io'
            ],
            
            # Cloud Storage (20+)
            'storage': [
                'dropbox.com', 'drive.google.com', 'onedrive.com', 'icloud.com',
                'box.com', 'mega.nz', 'sync.com', 'pcloud.com',
                'icedrive.net', 'tresorit.com', 'nextcloud.com', 'owncloud.com',
                'backblaze.com', 'carbonite.com', 'idrive.com', 'crashplan.com',
                's3.amazonaws.com', 'storage.googleapis.com', 'blob.core.windows.net',
                'digitalocean.com'
            ],
            
            # Security & VPN (25+)
            'security': [
                'nordvpn.com', 'expressvpn.com', 'surfshark.com', 'cyberghost.com',
                'privatevpn.com', 'purevpn.com', 'ipvanish.com', 'tunnelbear.com',
                'protonvpn.com', 'mullvad.net', 'windscribe.com', 'vypr.com',
                'lastpass.com', '1password.com', 'dashlane.com', 'bitwarden.com',
                'keeper.com', 'roboform.com', 'nortonlifelock.com', 'mcafee.com',
                'avg.com', 'avast.com', 'kaspersky.com', 'bitdefender.com',
                'malwarebytes.com'
            ]
        }
    
    def detect_lookalike(self, url: str) -> Dict[str, any]:
        """
        Detect if URL is a lookalike of a popular brand
        
        Returns:
            {
                'is_lookalike': bool,
                'lookalike_score': float (0-100),
                'matched_brand': str or None,
                'similarity_score': float (0-1),
                'distance': int,
                'homoglyph_detected': bool,
                'homoglyph_details': str or None
            }
        """
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain.lower()
            full_domain = f"{domain}.{extracted.suffix}".lower()
            
            best_match = None
            best_similarity = 0.0
            best_distance = 999
            best_category = None
            
            # Check against all brands
            for category, brands in self.brand_whitelist.items():
                for brand in brands:
                    brand_domain = brand.split('.')[0].lower()
                    
                    # Check if brand name is embedded in the domain (e.g., paypal in paypal-secure-verify)
                    if brand_domain in domain and brand_domain != domain:
                        # Brand name embedded in a longer domain - likely phishing
                        similarity = 0.95  # High similarity for embedded brands
                        distance = len(domain) - len(brand_domain)
                    else:
                        # Calculate Levenshtein distance
                        distance = lev_distance(domain, brand_domain)
                        
                        # Calculate similarity ratio
                        similarity = lev_ratio(domain, brand_domain)
                    
                    # Update best match
                    if similarity > best_similarity:
                        best_similarity = similarity
                        best_distance = distance
                        best_match = brand
                        best_category = category
            
            # Check for homoglyphs
            homoglyph_detected, homoglyph_details = self._check_homoglyphs(domain, best_match)
            
            # Determine if it's a lookalike
            is_lookalike = (
                best_similarity >= self.similarity_threshold and
                best_match and
                domain != best_match.split('.')[0].lower()
            ) or homoglyph_detected
            
            # Calculate lookalike score (0-100)
            lookalike_score = 0
            if is_lookalike:
                # Base score on similarity
                lookalike_score = int(best_similarity * 100)
                
                # Bonus for homoglyphs (more sophisticated attack)
                if homoglyph_detected:
                    lookalike_score = min(100, lookalike_score + 15)
                
                # Bonus for very high similarity
                if best_similarity > 0.95:
                    lookalike_score = min(100, lookalike_score + 10)
            
            return {
                'is_lookalike': is_lookalike,
                'lookalike_score': lookalike_score,
                'matched_brand': best_match if is_lookalike else None,
                'brand_category': best_category if is_lookalike else None,
                'similarity_score': round(best_similarity, 4),
                'levenshtein_distance': best_distance,
                'homoglyph_detected': homoglyph_detected,
                'homoglyph_details': homoglyph_details
            }
            
        except Exception as e:
            logger.error(f"Error in lookalike detection: {e}")
            return self._get_default_result()
    
    def _check_homoglyphs(self, domain: str, brand: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Check for homoglyph character substitutions"""
        if not brand:
            return False, None
        
        brand_domain = brand.split('.')[0].lower()
        
        # Check each character
        for i, (char_d, char_b) in enumerate(zip(domain, brand_domain)):
            if char_d != char_b:
                # Check if it's a known homoglyph
                if char_b in self.homoglyphs:
                    if char_d in self.homoglyphs[char_b]:
                        return True, f"Uses '{char_d}' instead of '{char_b}' at position {i+1}"
                
                # Check reverse (char_d is the legitimate one)
                if char_d in self.homoglyphs:
                    if char_b in self.homoglyphs[char_d]:
                        return True, f"Uses '{char_d}' instead of '{char_b}' at position {i+1}"
        
        # Check for mixed-script attacks (different unicode ranges)
        try:
            domain_scripts = set()
            for char in domain:
                if 'а' <= char <= 'я' or 'А' <= char <= 'Я':
                    domain_scripts.add('cyrillic')
                elif 'α' <= char <= 'ω' or 'Α' <= char <= 'Ω':
                    domain_scripts.add('greek')
                elif char.isalpha():
                    domain_scripts.add('latin')
            
            if len(domain_scripts) > 1:
                return True, f"Mixed scripts detected: {', '.join(domain_scripts)}"
        except Exception as e:
            logger.debug(f"Error checking scripts: {e}")
        
        return False, None
    
    def _get_default_result(self) -> Dict[str, any]:
        """Return default result on error"""
        return {
            'is_lookalike': False,
            'lookalike_score': 0,
            'matched_brand': None,
            'brand_category': None,
            'similarity_score': 0.0,
            'levenshtein_distance': 999,
            'homoglyph_detected': False,
            'homoglyph_details': None
        }
    
    def get_all_brands(self) -> List[str]:
        """Get list of all protected brands"""
        all_brands = []
        for brands in self.brand_whitelist.values():
            all_brands.extend(brands)
        return sorted(all_brands)
    
    def get_brand_count(self) -> int:
        """Get total number of protected brands"""
        return sum(len(brands) for brands in self.brand_whitelist.values())


# Global instance
lookalike_detector = LookalikeDomainDetector()
