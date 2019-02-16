using DotNetCoreArchitecture.Model;

namespace DotNetCoreArchitecture.Domain
{
    public sealed class UserDomain
    {
        public UserDomain
        (
            long userId,
            string name,
            string surname,
            string email,
            string login,
            string password,
            Roles roles
        )
        {
            UserId = userId;
            Name = name;
            Surname = surname;
            Email = email;
            Login = login;
            Password = password;
            Roles = roles;
        }

        public UserDomain(string login, string password)
        {
            Login = login;
            Password = password;
        }

        public string Email { get; private set; }

        public string Login { get; private set; }

        public string Name { get; private set; }

        public string Password { get; private set; }

        public Roles Roles { get; set; }

        public Status Status { get; set; }

        public string Surname { get; private set; }

        public long UserId { get; private set; }

        public void Add()
        {
            Roles = Roles.User;
            Status = Status.Active;
            CreateLoginPasswordHash();
        }

        public void SetLogin(string login)
        {
            Login = login;
        }

        public void SetPassword(string password)
        {
            Password = password;
        }

        public void SignIn()
        {
            CreateLoginPasswordHash();
        }

        private void CreateLoginPasswordHash()
        {
            Login = UserDomainService.CreateHash(Login);
            Password = UserDomainService.CreateHash(Password);
        }
    }
}
