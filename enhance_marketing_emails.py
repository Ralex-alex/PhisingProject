import os
import pandas as pd
import random
from datetime import datetime, timedelta
import re
from tqdm import tqdm
import json
import logging
import argparse
import sys

logger = logging.getLogger(__name__)

class MarketingEmailGenerator:
    """
    Class to generate realistic marketing emails to enhance the training dataset
    for better recognition of legitimate marketing content.
    
    This class helps reduce false positives in phishing detection by providing
    examples of legitimate marketing communications from popular services.
    """
    
    def __init__(self, output_dir="enhanced_data"):
        """
        Initialize the marketing email generator.
        
        The generator creates a dedicated directory to store generated emails
        and maintains templates for various types of marketing communications.
        
        Args:
            output_dir (str): Directory to store generated emails and related data
        """
        # Create output directory if it doesn't exist
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Common gaming-related words for generating realistic stream titles
        self.gaming_words = [
            "stream", "gaming", "live", "playing", "speedrun",
            "ranked", "competitive", "casual", "playthrough",
            "first time", "pro", "noob", "challenge"
        ]
        
        # List of popular games for generating content
        self.games = [
            "Minecraft", "Fortnite", "League of Legends",
            "Valorant", "Among Us", "Call of Duty", "CS:GO",
            "Apex Legends", "GTA V", "Dota 2", "Overwatch",
            "PUBG", "Rocket League"
        ]
        
        # Music genres for Spotify notifications
        self.music_genres = [
            "Pop", "Rock", "Hip Hop", "Electronic", "Classical",
            "Jazz", "Metal", "Indie", "Folk", "R&B", "Country"
        ]
        
        # Common marketing phrases
        self.marketing_phrases = [
            "Don't miss out", "Limited time offer",
            "New release", "Just for you", "Trending now",
            "Popular in your area", "Recommended",
            "Based on your interests", "Special offer",
            "Exclusive content"
        ]
        
        # Email templates for different types of notifications
        self.templates = {
            "twitch": {
                "subjects": [
                    "{streamer} is now live: {title}",
                    "🔴 LIVE: {streamer} - {title}",
                    "{streamer} started streaming {game}"
                ],
                "bodies": [
                    "Your favorite streamer is live!\n\n"
                    "Stream: {title}\n"
                    "Game: {game}\n"
                    "Started at: {time}\n\n"
                    "Don't miss out! Click here to watch: {link}"
                ]
            },
            # Add more templates for other services...
        }
        
        # Common marketing email senders
        self.senders = [
            "newsletter@amazon.com", "info@netflix.com", "no-reply@twitch.tv",
            "news@spotify.com", "updates@youtube.com", "hello@discord.com",
            "newsletter@steam.com", "marketing@epicgames.com", "notifications@instagram.com",
            "updates@twitter.com", "newsletter@linkedin.com", "no-reply@facebook.com",
            "offers@walmart.com", "deals@bestbuy.com", "newsletter@target.com",
            "info@uber.com", "receipts@doordash.com", "no-reply@grubhub.com"
        ]
        
        # Streaming notification templates
        self.streaming_templates = [
            "{streamer} is now live on {platform}!",
            "Your favorite streamer {streamer} is live!",
            "Don't miss {streamer}'s stream on {platform}!",
            "Live now: {streamer} on {platform}",
            "{streamer} just started streaming {game}",
            "Watch {streamer} play {game} live now!",
            "{streamer} is streaming! Click to watch now.",
            "Your {platform} notification: {streamer} is live"
        ]
        
        # Streamer names
        self.streamers = [
            "Ninja", "Pokimane", "xQc", "Shroud", "TimTheTatman", "DrLupo",
            "Valkyrae", "Sykkuno", "Ludwig", "DrDisrespect", "Amouranth",
            "Sodapoppin", "Asmongold", "HasanAbi", "Mizkif", "Emiru",
            "LilyPichu", "Disguised Toast", "Summit1g", "NICKMERCS"
        ]
        
        # Streaming platforms
        self.platforms = ["Twitch", "YouTube", "Kick", "Facebook Gaming", "TikTok Live"]
        
        # Emoji sets for different types of marketing emails
        self.emojis = {
            "gaming": ["🎮", "🕹️", "👾", "🎯", "🏆", "⚔️", "🛡️", "🔥", "⭐", "💥", "🎲"],
            "shopping": ["🛍️", "💰", "💲", "💸", "🏷️", "🎁", "✨", "💯", "🆕", "🔥", "💝"],
            "streaming": ["📺", "🎬", "🍿", "🎥", "📽️", "🎞️", "📱", "💻", "🖥️", "📡", "🎭"],
            "music": ["🎵", "🎶", "🎧", "🎸", "🥁", "🎹", "🎷", "🎺", "🎻", "🎤", "🎼"],
            "social": ["👋", "👍", "❤️", "🤩", "😊", "🙌", "👏", "💬", "📱", "💌", "🌟"]
        }
        
    def generate_twitch_notification(self):
        """
        Generate a realistic Twitch streaming notification email.
        
        This method creates an email that mimics Twitch's notification system,
        including stream title, game being played, and streamer information.
        The format closely matches real Twitch emails to help train the
        system to recognize legitimate gaming-related communications.
        
        Returns:
            dict: Email data including subject, body, sender, and metadata
        """
        # Select a random streamer name
        streamer = random.choice(self.streamers)
        
        # Generate a realistic stream title
        game = random.choice(self.games)
        title = self._generate_stream_title(game)
        
        # Create a realistic Twitch tracking link
        stream_id = self._generate_random_id(10)
        tracking_id = self._generate_random_id(8)
        link = f"https://www.twitch.tv/{streamer.lower()}?tt_content=stream_title&tt_medium=email&tt_id={tracking_id}"
        
        # Generate timestamp for the stream
        current_time = datetime.now()
        stream_time = current_time.strftime("%I:%M %p")
        
        # Select email template and format with content
        subject = random.choice(self.templates["twitch"]["subjects"]).format(
            streamer=streamer,
            title=title,
            game=game
        )
        
        body = random.choice(self.templates["twitch"]["bodies"]).format(
            streamer=streamer,
            title=title,
            game=game,
            time=stream_time,
            link=link
        )
        
        # Add standard Twitch footer with unsubscribe link
        footer = (
            "\n\n---\n"
            "You are receiving this email because you follow {streamer} on Twitch. "
            "To stop receiving these emails, unsubscribe here: "
            "https://www.twitch.tv/settings/notifications/{user_id}"
        ).format(streamer=streamer, user_id=self._generate_random_id(12))
        
        body += footer
        
        return {
            "subject": subject,
            "body": body,
            "sender": "notifications@twitch.tv",
            "type": "twitch_notification",
            "timestamp": current_time.isoformat(),
            "metadata": {
                "streamer": streamer,
                "game": game,
                "stream_id": stream_id,
                "tracking_id": tracking_id
            }
        }
    
    def generate_youtube_notification(self):
        """
        Generate a realistic YouTube video notification email.
        
        Creates an email that mimics YouTube's notification system for new video
        uploads, including video title, channel name, and engagement metrics.
        Follows YouTube's actual email format to help the system recognize
        legitimate YouTube communications.
        
        Returns:
            dict: Email data including subject, body, sender, and metadata
        """
        # Select a random channel name and generate video details
        channel = random.choice(self.streamers)
        video_id = self._generate_random_id(11)  # YouTube uses 11-char video IDs
        
        # Generate realistic video title and metrics
        title = f"{random.choice(self.marketing_phrases)} - {random.choice(self.games)} {random.choice(['Gameplay', 'Review', 'Guide', 'Highlights'])}"
        views = random.randint(100, 50000)
        duration = f"{random.randint(5, 30)}:{random.randint(10, 59)}"
        
        # Create YouTube tracking link
        tracking_id = self._generate_random_id(16)
        link = f"https://www.youtube.com/watch?v={video_id}&utm_source=notification&utm_medium=email&utm_campaign=upload&tracking={tracking_id}"
        
        # Format email content
        subject = f"{channel} uploaded: {title}"
        
        body = (
            f"New video from {channel}\n\n"
            f"{title}\n"
            f"Duration: {duration}\n"
            f"Views: {views}\n\n"
            f"Watch now: {link}\n"
        )
        
        # Add YouTube-style footer
        footer = (
            "\n---\n"
            "This email was sent by YouTube to users who requested notifications. "
            "To update your notification preferences, visit your YouTube settings."
        )
        
        body += footer
        
        return {
            "subject": subject,
            "body": body,
            "sender": "noreply@youtube.com",
            "type": "youtube_notification",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "channel": channel,
                "video_id": video_id,
                "tracking_id": tracking_id,
                "metrics": {
                    "views": views,
                    "duration": duration
                }
            }
        }
    
    def generate_discord_notification(self):
        """
        Generate a realistic Discord notification email.
        
        Creates an email that mimics Discord's notification system for new messages,
        server invites, and friend requests. Includes Discord's characteristic
        formatting and branding to help train the system on legitimate Discord emails.
        
        Returns:
            dict: Email data including subject, body, sender, and metadata
        """
        # Generate random Discord-specific details
        server_name = random.choice([
            "Gaming Hub", "Esports Central", "Minecraft World",
            "Study Group", "Book Club", "Music Lovers",
            "Art Community", "Tech Support", "Friend Group"
        ])
        
        # Create a realistic Discord tracking ID and server ID
        server_id = self._generate_random_id(18)  # Discord uses 18-digit IDs
        tracking = self._generate_random_id(32)
        
        # Generate notification type and content
        notification_types = ["message", "invite", "friend_request", "mention"]
        notif_type = random.choice(notification_types)
        
        if notif_type == "message":
            subject = f"New messages in {server_name}"
            content = f"You have new messages in the #{random.choice(['general', 'gaming', 'chat', 'announcements'])} channel"
        elif notif_type == "invite":
            subject = f"You've been invited to join {server_name}"
            content = f"A server admin has invited you to join their community"
        elif notif_type == "friend_request":
            username = f"{random.choice(['Cool', 'Pro', 'Epic', 'Gaming'])}User#{random.randint(1000, 9999)}"
            subject = f"New Friend Request from {username}"
            content = f"{username} wants to add you as a friend"
        else:  # mention
            subject = f"You were mentioned in {server_name}"
            content = f"Someone mentioned you in #{random.choice(['general', 'gaming', 'chat'])}"
        
        # Create Discord-style link with tracking
        link = f"https://discord.com/channels/{server_id}?tracking={tracking}"
        
        # Format the email body with Discord's style
        body = (
            f"{content}\n\n"
            f"To respond to this notification, click here: {link}\n\n"
            "---\n"
            "You're receiving this email because you enabled notifications for Discord.\n"
            "To modify these email settings, check your Discord Notification Settings."
        )
        
        return {
            "subject": subject,
            "body": body,
            "sender": "noreply@discord.com",
            "type": "discord_notification",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "notification_type": notif_type,
                "server_name": server_name,
                "server_id": server_id,
                "tracking_id": tracking
            }
        }
    
    def generate_steam_notification(self):
        """
        Generate a realistic Steam notification email.
        
        Creates an email that mimics Steam's notification system for game updates,
        wishlist sales, and friend activity. Includes Steam's formatting and
        security notices to help identify legitimate Steam communications.
        
        Returns:
            dict: Email data including subject, body, sender, and metadata
        """
        # Generate Steam-specific notification details
        notification_types = ["wishlist_sale", "game_update", "friend_activity", "new_release"]
        notif_type = random.choice(notification_types)
        
        # Select a random game and generate Steam-specific IDs
        game = random.choice(self.games)
        app_id = random.randint(100000, 999999)  # Steam app IDs are 6 digits
        tracking = self._generate_random_id(32)
        
        # Generate price and discount for sales
        original_price = random.randint(20, 60)
        discount = random.choice([10, 25, 33, 50, 75])
        sale_price = original_price * (1 - discount/100)
        
        # Format currency for display
        formatted_original = f"${original_price:.2f}"
        formatted_sale = f"${sale_price:.2f}"
        
        if notif_type == "wishlist_sale":
            subject = f"Special Offer: {game} is now on sale!"
            content = (
                f"A game on your wishlist is on sale!\n\n"
                f"{game} - {discount}% OFF\n"
                f"Original price: {formatted_original}\n"
                f"Sale price: {formatted_sale}\n"
                f"Offer ends in {random.randint(1, 7)} days"
            )
        elif notif_type == "game_update":
            subject = f"Update Available: {game}"
            content = (
                f"An update is available for {game}\n\n"
                f"Update size: {random.randint(100, 2000)}MB\n"
                f"View patch notes and details on Steam"
            )
        elif notif_type == "friend_activity":
            friend = f"Player{random.randint(1000, 9999)}"
            subject = f"Your friend {friend} is playing {game}"
            content = (
                f"{friend} is now playing {game}\n"
                f"Click here to join their game"
            )
        else:  # new_release
            subject = f"Now Available on Steam: {game}"
            content = (
                f"{game} is now available on Steam!\n\n"
                f"Launch Price: {formatted_original}\n"
                f"Special offer: Buy in the first week and save {discount}%"
            )
        
        # Create Steam-style link with tracking
        link = f"https://store.steampowered.com/app/{app_id}/?utm_source=email&utm_medium=notification&tracking={tracking}"
        
        # Format the email body with Steam's style
        body = (
            f"{content}\n\n"
            f"View on Steam: {link}\n\n"
            "---\n"
            "This email was sent by Steam because you have notifications enabled.\n"
            "To change your email preferences, visit your Steam Account Settings page.\n\n"
            "For your security, never enter your Steam password unless you're on store.steampowered.com"
        )
        
        return {
            "subject": subject,
            "body": body,
            "sender": "noreply@steampowered.com",
            "type": "steam_notification",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "notification_type": notif_type,
                "game": game,
                "app_id": app_id,
                "tracking_id": tracking,
                "price_data": {
                    "original": original_price,
                    "discount": discount,
                    "sale": sale_price
                } if notif_type in ["wishlist_sale", "new_release"] else None
            }
        }
    
    def generate_spotify_notification(self):
        """
        Generate a realistic Spotify notification email.
        
        Creates an email that mimics Spotify's notification system for new releases,
        playlist updates, and listening recommendations. Includes Spotify's branding
        and formatting to help identify legitimate Spotify communications.
        
        Returns:
            dict: Email data including subject, body, sender, and metadata
        """
        # Generate Spotify-specific notification details
        notification_types = ["new_release", "playlist_update", "weekly_discovery", "friend_activity"]
        notif_type = random.choice(notification_types)
        
        # Create Spotify-style IDs and tracking
        playlist_id = self._generate_random_id(22)  # Spotify uses 22-char IDs
        tracking = self._generate_random_id(32)
        
        # Generate artist and track details
        artist = random.choice([
            "The Digital Dreams", "Cyber Symphony", "Electronic Pulse",
            "Virtual Reality", "Tech Beats", "Future Sound",
            "Quantum Wave", "Binary Echo", "Neural Network"
        ])
        
        # Select genre and create track name
        genre = random.choice(self.music_genres)
        track = f"{random.choice(['Dreams', 'Night', 'Love', 'Life', 'Time', 'World', 'Heart'])} {random.choice(['of', 'in', 'through', 'beyond'])} {random.choice(['Tomorrow', 'Forever', 'Tonight', 'Reality', 'Space'])}"
        
        if notif_type == "new_release":
            subject = f"New Release from {artist}"
            content = (
                f"{artist} just released new music\n\n"
                f"New {random.choice(['Single', 'Album', 'EP'])}: {track}\n"
                f"Genre: {genre}\n"
                f"Duration: {random.randint(2, 4)}:{random.randint(10, 59)}"
            )
        elif notif_type == "playlist_update":
            playlist_name = f"{genre} {random.choice(['Mix', 'Vibes', 'Essentials', 'Hits'])}"
            subject = f"New songs added to {playlist_name}"
            content = (
                f"We've updated {playlist_name} with fresh tracks\n\n"
                f"Including new music from:\n"
                f"• {artist}\n"
                f"• And more..."
            )
        elif notif_type == "weekly_discovery":
            subject = "Your Weekly Discovery Mix is ready"
            content = (
                f"New music picked just for you\n\n"
                f"This week featuring:\n"
                f"• {track} by {artist}\n"
                f"• Plus 30 more songs we think you'll love"
            )
        else:  # friend_activity
            friend = f"User{random.randint(1000, 9999)}"
            subject = f"See what {friend} is listening to"
            content = (
                f"{friend} is on a {genre} kick\n\n"
                f"Currently playing:\n"
                f"{track} by {artist}"
            )
        
        # Create Spotify-style link with tracking
        link = f"https://open.spotify.com/playlist/{playlist_id}?si={tracking}"
        
        # Format the email body with Spotify's style
        body = (
            f"{content}\n\n"
            f"Listen on Spotify: {link}\n\n"
            "---\n"
            "This email was sent by Spotify as part of your notification preferences.\n"
            "To manage your email notifications, visit your Spotify Account Settings."
        )
        
        return {
            "subject": subject,
            "body": body,
            "sender": "no-reply@spotify.com",
            "type": "spotify_notification",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "notification_type": notif_type,
                "artist": artist,
                "track": track,
                "genre": genre,
                "playlist_id": playlist_id,
                "tracking_id": tracking
            }
        }
    
    def generate_newsletter_email(self):
        """
        Generate a realistic marketing newsletter email.
        
        Creates a newsletter-style marketing email with common elements like
        promotional offers, product updates, and calls to action. Uses standard
        marketing practices and formatting to help identify legitimate marketing emails.
        
        Returns:
            dict: Email data including subject, body, sender, and metadata
        """
        # Select company and generate campaign details
        company = random.choice([
            "TechGear", "GameStation", "FashionHub", "HomeStyle",
            "FoodDelight", "SportZone", "BookWorld", "ArtSpace"
        ])
        
        campaign_id = self._generate_random_id(16)
        tracking = self._generate_random_id(32)
        
        # Generate promotional content
        promo_types = ["sale", "new_product", "special_offer", "seasonal"]
        promo_type = random.choice(promo_types)
        
        # Generate discount and pricing details
        discount = random.choice([10, 15, 20, 25, 30, 40, 50])
        min_purchase = random.choice([0, 25, 50, 75, 100])
        
        if promo_type == "sale":
            subject = f"🔥 {discount}% OFF Everything at {company}"
            content = (
                f"HUGE SALE - Save {discount}% on all products!\n\n"
                f"• Minimum purchase: ${min_purchase}\n"
                f"• Limited time offer\n"
                f"• Free shipping on orders over ${min_purchase + 50}"
            )
        elif promo_type == "new_product":
            subject = f"New Arrivals at {company} 🆕"
            content = (
                f"Check out our latest products!\n\n"
                f"• Exclusive launch discounts\n"
                f"• Early bird special: Save {discount}%\n"
                f"• Free shipping on your first order"
            )
        elif promo_type == "special_offer":
            subject = f"Special Offer Just for You! 🎁"
            content = (
                f"As a valued customer, you get:\n\n"
                f"• Extra {discount}% off your next purchase\n"
                f"• Double reward points\n"
                f"• Free gift with orders over ${min_purchase}"
            )
        else:  # seasonal
            season = random.choice(["Summer", "Winter", "Spring", "Fall"])
            subject = f"🌟 {season} Sale at {company}"
            content = (
                f"Get ready for {season}!\n\n"
                f"• Seasonal discounts up to {discount}%\n"
                f"• New {season.lower()} collection\n"
                f"• Limited time offers"
            )
        
        # Create marketing link with tracking
        link = f"https://www.{company.lower()}.com/promo/{campaign_id}?utm_source=email&utm_campaign={promo_type}&tracking={tracking}"
        
        # Format the email body with standard marketing elements
        body = (
            f"{content}\n\n"
            f"Shop Now: {link}\n\n"
            "---\n"
            f"This email was sent to you because you subscribed to {company} marketing emails.\n"
            "To unsubscribe or manage your preferences, click here.\n\n"
            f"{company} Inc. | Privacy Policy | Terms of Service"
        )
        
        return {
            "subject": subject,
            "body": body,
            "sender": f"marketing@{company.lower()}.com",
            "type": "newsletter",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "company": company,
                "campaign_type": promo_type,
                "campaign_id": campaign_id,
                "tracking_id": tracking,
                "promotion_details": {
                    "discount": discount,
                    "minimum_purchase": min_purchase
                }
            }
        }
    
    def _generate_stream_title(self, game):
        """
        Generate a realistic streaming title for gaming content.
        
        Creates engaging stream titles that mimic real gaming streams,
        including common gaming terminology, emojis, and formatting patterns.
        
        Args:
            game (str): Name of the game being streamed
            
        Returns:
            str: Generated stream title
        """
        # Common stream title patterns
        patterns = [
            "{game} {type} | {extra}",
            "🎮 {game} | {type} | {extra}",
            "{type}: {game} | {extra}",
            "{game} {rank} | {type} | {extra}"
        ]
        
        # Stream types and extras for variety
        stream_types = [
            "Ranked Grind", "Casual Games", "Pro Scrims",
            "Community Games", "Tournament Practice",
            "Speedruns", "First Playthrough"
        ]
        
        rank_terms = [
            "Diamond", "Master", "Challenger", "Global Elite",
            "Radiant", "Immortal", "Predator", "Top 500"
        ]
        
        extra_phrases = [
            "!drops enabled", "!giveaway", "New Season",
            "Patch {}.{} Meta".format(random.randint(1, 9), random.randint(0, 9)),
            "Road to {} followers".format(random.randint(1000, 10000)),
            "Day {} of streaming".format(random.randint(1, 365))
        ]
        
        # Generate title components
        pattern = random.choice(patterns)
        stream_type = random.choice(stream_types)
        extra = random.choice(extra_phrases)
        
        # Add rank information sometimes
        if "{rank}" in pattern:
            stream_type = random.choice(rank_terms)
        
        # Format the title
        title = pattern.format(
            game=game,
            type=stream_type,
            extra=extra,
            rank=random.choice(rank_terms)
        )
        
        return title
    
    def _generate_random_id(self, length):
        """
        Generate a random ID string of specified length.
        
        Creates random IDs for various purposes like tracking codes,
        campaign IDs, and content identifiers. Uses a mix of letters
        and numbers to match common ID formats.
        
        Args:
            length (int): Length of the ID to generate
            
        Returns:
            str: Generated random ID
        """
        # Characters to use in ID generation
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def generate_marketing_emails(self, count=500):
        """
        Generate a batch of marketing emails for training.
        
        Creates a diverse set of marketing emails using different templates
        and styles to help train the system on legitimate marketing content.
        Includes various types of notifications and promotional content.
        
        Args:
            count (int): Number of emails to generate
            
        Returns:
            pd.DataFrame: DataFrame containing generated emails
        """
        logger.info(f"Generating {count} marketing emails...")
        
        # List to store generated emails
        emails = []
        
        # Generator functions for different email types
        generators = {
            "twitch": self.generate_twitch_notification,
            "youtube": self.generate_youtube_notification,
            "discord": self.generate_discord_notification,
            "steam": self.generate_steam_notification,
            "spotify": self.generate_spotify_notification,
            "newsletter": self.generate_newsletter_email
        }
        
        # Generate emails with progress bar
        with tqdm(total=count, desc="Generating emails") as pbar:
            while len(emails) < count:
                # Select random generator
                generator_type = random.choice(list(generators.keys()))
                generator_func = generators[generator_type]
                
                try:
                    # Generate email
                    email = generator_func()
                    
                    # Add to collection
                    emails.append({
                        "subject": email["subject"],
                        "body": email["body"],
                        "sender": email["sender"],
                        "type": email["type"],
                        "timestamp": email["timestamp"],
                        "is_marketing": True,
                        "metadata": json.dumps(email["metadata"])
                    })
                    
                    pbar.update(1)
                    
                except Exception as e:
                    logger.error(f"Error generating {generator_type} email: {e}")
                    continue
        
        # Convert to DataFrame
        df = pd.DataFrame(emails)
        
        # Add additional metadata
        df["generation_date"] = datetime.now().isoformat()
        df["source"] = "generated"
        
        return df
    
    def save_to_csv(self, df, filename="marketing_emails.csv"):
        """
        Save generated emails to a CSV file.
        
        Saves the DataFrame of generated emails with proper encoding
        and formatting. Creates the output directory if it doesn't exist.
        
        Args:
            df (pd.DataFrame): DataFrame of generated emails
            filename (str): Name of the output file
            
        Returns:
            str: Path to the saved file
        """
        # Create output path
        output_path = os.path.join(self.output_dir, filename)
        
        # Save to CSV
        df.to_csv(output_path, index=False, encoding='utf-8')
        logger.info(f"Saved {len(df)} emails to {output_path}")
        
        return output_path
    
    def enhance_existing_dataset(self, original_dataset_path, output_filename="enhanced_dataset.csv"):
        """
        Enhance an existing email dataset with generated marketing emails.
        
        Takes an existing dataset and adds generated marketing emails to it,
        helping to improve the system's ability to distinguish between
        legitimate marketing emails and phishing attempts.
        
        Args:
            original_dataset_path (str): Path to original dataset
            output_filename (str): Name for the enhanced dataset file
            
        Returns:
            str: Path to the enhanced dataset
        """
        try:
            # Load original dataset
            original_df = pd.read_csv(original_dataset_path)
            logger.info(f"Loaded original dataset with {len(original_df)} entries")
            
            # Count legitimate vs phishing emails
            phishing_count = sum(original_df["is_phishing"])
            legitimate_count = len(original_df) - phishing_count
            
            # Generate marketing emails (20% of original dataset size)
            marketing_count = int(len(original_df) * 0.2)
            marketing_df = self.generate_marketing_emails(count=marketing_count)
            
            # Combine datasets
            enhanced_df = pd.concat([original_df, marketing_df], ignore_index=True)
            
            # Save enhanced dataset
            output_path = os.path.join(self.output_dir, output_filename)
            enhanced_df.to_csv(output_path, index=False, encoding='utf-8')
            
            logger.info(f"Enhanced dataset saved with {len(enhanced_df)} entries")
            logger.info(f"Original phishing emails: {phishing_count}")
            logger.info(f"Original legitimate emails: {legitimate_count}")
            logger.info(f"Added marketing emails: {len(marketing_df)}")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Error enhancing dataset: {e}")
            raise

if __name__ == "__main__":
    """
    Main execution block for the marketing email generator.
    
    This script can be run directly to:
    1. Generate a new set of marketing emails
    2. Enhance an existing dataset with marketing emails
    3. Save the results to CSV files
    
    The script uses command line arguments to control its behavior:
    --dataset: Path to an existing dataset to enhance
    --output: Name of the output file
    --count: Number of marketing emails to generate
    """
    # Set up logging configuration
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Generate marketing emails for training")
    parser.add_argument("--dataset", help="Path to existing dataset to enhance")
    parser.add_argument("--output", default="marketing_emails.csv", help="Output filename")
    parser.add_argument("--count", type=int, default=500, help="Number of marketing emails to generate")
    args = parser.parse_args()
    
    try:
        # Initialize the generator
        generator = MarketingEmailGenerator()
        
        if args.dataset:
            # Enhance existing dataset
            logger.info(f"Enhancing dataset: {args.dataset}")
            output_path = generator.enhance_existing_dataset(
                args.dataset,
                output_filename=args.output
            )
            logger.info(f"Enhanced dataset saved to: {output_path}")
        else:
            # Generate new marketing emails
            logger.info(f"Generating {args.count} new marketing emails")
            marketing_df = generator.generate_marketing_emails(count=args.count)
            output_path = generator.save_to_csv(marketing_df, filename=args.output)
            logger.info(f"Marketing emails saved to: {output_path}")
            
    except Exception as e:
        logger.error(f"Error in main execution: {e}", exc_info=True)
        sys.exit(1) 