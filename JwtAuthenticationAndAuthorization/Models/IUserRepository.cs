namespace JwtAuthenticationAndAuthorization.Models
{
    public interface IUserRepository
    {
        void AddUser(User user);
        User GetUser(string username);
    }
}
