class User < ActiveRecord::Base
  
  has_many :microposts, dependent: :destroy
  
  attr_accessor :remember_token, :activation_token, :reset_token
  before_save :downcase_email
  before_create :create_activation_digest
  
  validates :name, presence: true, length: {maximum: 50}
  
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates :email, presence: true, length: { maximum: 255 },
                    format: { with: VALID_EMAIL_REGEX }, 
                    uniqueness: {case_sensitive: false}
  
  has_secure_password
  validates :password, presence: true, length: {minimum: 6}, allow_nil: true
  
  # Returns the hash digest of the given string.
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
                                                  BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end
  
  # Generates a new token to be used in different methods
  def User.new_token
    SecureRandom.urlsafe_base64
  end
  
  # Generates a remember token and updates the remember digest attribute
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end
  
  # A generalized method to create a 'digest' which takes two inputs
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest")
    return false if digest.nil?
    BCrypt::Password.new(digest).is_password?(token)
  end
  
  # Forgets the user (Deletes the remember me digest from the digest upon logging out)
  def forget
    update_attribute(:remember_digest, nil)
  end
  
  # Activates the account
  def activate
    update_attribute(:activated, true)
    update_attribute(:activated_at, Time.zone.now)
  end
  
  # Sends the activation mail
  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end
  
  # Creates reset token and reset digest updates the attributes
  def create_reset_digest
    self.reset_token = User.new_token
    update_attribute(:reset_digest, User.digest(reset_token))
    update_attribute(:reset_sent_at, Time.zone.now)
  end
  
  # Sends the password reset email
  def send_password_reset_email
    UserMailer.password_reset(self).deliver_now
  end
  
  # Checks whether password reset link has been expired or not
  def password_reset_expired?
    reset_sent_at < 2.hours.ago
  end
  
  # Defines a proto-feed
  def feed
    Micropost.where("user_id = ?", id)
  end
  
  private
    
    # Converts email to lower-case
    def downcase_email
      self.email = email.downcase
    end
    
    # Creates and assigns the activation token and digest
    def create_activation_digest
      self.activation_token = User.new_token
      self.activation_digest = User.digest(activation_token)
    end
  
end
