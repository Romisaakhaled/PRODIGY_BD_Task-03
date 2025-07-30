namespace JwtAuthenticationAndAuthorization.Models
{
    public class InMemoryUserRepository : IUserRepository
    {
        private readonly Dictionary<string, User> _users = new();

        public void AddUser(User user) => _users[user.Username] = user;

        public User GetUser(string username) => _users.TryGetValue(username, out var user) ? user : null;
    }

}
