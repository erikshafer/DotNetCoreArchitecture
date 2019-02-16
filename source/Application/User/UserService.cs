using DotNetCore.Mapping;
using DotNetCore.Objects;
using DotNetCore.Security;
using DotNetCoreArchitecture.Database;
using DotNetCoreArchitecture.Domain;
using DotNetCoreArchitecture.Model;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DotNetCoreArchitecture.Application
{
    public sealed class UserService : IUserService
    {
        public UserService
        (
            IDatabaseUnitOfWork databaseUnitOfWork,
            IJsonWebToken jsonWebToken,
            IUserLogService userLogService,
            IUserRepository userRepository
        )
        {
            DatabaseUnitOfWork = databaseUnitOfWork;
            JsonWebToken = jsonWebToken;
            UserLogService = userLogService;
            UserRepository = userRepository;
        }

        private IDatabaseUnitOfWork DatabaseUnitOfWork { get; }

        private IJsonWebToken JsonWebToken { get; }

        private IUserLogService UserLogService { get; }

        private IUserRepository UserRepository { get; }

        public async Task<IDataResult<long>> AddAsync(AddUserModel addUserModel)
        {
            var validation = new AddUserModelValidator().Valid(addUserModel);

            if (!validation.Success)
            {
                return new ErrorDataResult<long>(validation.Message);
            }

            var userDomain = UserDomainFactory.Create(addUserModel);

            userDomain.Add();

            var userEntity = userDomain.Map<UserEntity>();

            await UserRepository.AddAsync(userEntity).ConfigureAwait(false);

            await DatabaseUnitOfWork.SaveChangesAsync().ConfigureAwait(false);

            return new SuccessDataResult<long>(userEntity.UserId);
        }

        public async Task<IResult> DeleteAsync(long userId)
        {
            await UserRepository.DeleteAsync(userId).ConfigureAwait(false);

            await DatabaseUnitOfWork.SaveChangesAsync().ConfigureAwait(false);

            return new SuccessResult();
        }

        public async Task<PagedList<UserModel>> ListAsync(PagedListParameters parameters)
        {
            return await UserRepository.ListAsync<UserModel>(parameters).ConfigureAwait(false);
        }

        public async Task<IEnumerable<UserModel>> ListAsync()
        {
            return await UserRepository.ListAsync<UserModel>().ConfigureAwait(false);
        }

        public async Task<UserModel> SelectAsync(long userId)
        {
            return await UserRepository.SelectAsync<UserModel>(userId).ConfigureAwait(false);
        }

        public async Task<IDataResult<TokenModel>> SignInAsync(SignInModel signInModel)
        {
            var validation = new SignInModelValidator().Valid(signInModel);

            if (!validation.Success)
            {
                return new ErrorDataResult<TokenModel>(validation.Message);
            }

            var userDomain = UserDomainFactory.Create(signInModel);

            userDomain.SignIn();

            signInModel = userDomain.Map<SignInModel>();

            var signedInModel = await UserRepository.SignInAsync(signInModel).ConfigureAwait(false);

            validation = new SignedInModelValidator().Valid(signedInModel);

            if (!validation.Success)
            {
                return new ErrorDataResult<TokenModel>(validation.Message);
            }

            await AddUserLogAsync(signedInModel.UserId, LogType.SignIn).ConfigureAwait(false);

            var tokenModel = CreateJsonWebToken(signedInModel);

            return new SuccessDataResult<TokenModel>(tokenModel);
        }

        public async Task SignOutAsync(SignOutModel signOutModel)
        {
            await AddUserLogAsync(signOutModel.UserId, LogType.SignOut).ConfigureAwait(false);
        }

        public async Task<IResult> UpdateAsync(UpdateUserModel updateUserModel)
        {
            var validation = new UpdateUserModelValidator().Valid(updateUserModel);

            if (!validation.Success)
            {
                return new ErrorResult(validation.Message);
            }

            var userEntityDatabase = await UserRepository.SelectAsync(updateUserModel.UserId).ConfigureAwait(false);

            var userDomain = UserDomainFactory.Create(updateUserModel);

            userDomain.SetLogin(userEntityDatabase.Login);

            userDomain.SetPassword(userEntityDatabase.Password);

            var userEntity = userDomain.Map<UserEntity>();

            await UserRepository.UpdateAsync(userEntity, userEntity.UserId).ConfigureAwait(false);

            await DatabaseUnitOfWork.SaveChangesAsync().ConfigureAwait(false);

            return new SuccessResult();
        }

        private async Task AddUserLogAsync(long userId, LogType logType)
        {
            var userLogModel = new UserLogModel(userId, logType);

            await UserLogService.AddAsync(userLogModel).ConfigureAwait(false);
        }

        private TokenModel CreateJsonWebToken(SignedInModel signedInModel)
        {
            var sub = signedInModel.UserId.ToString();

            var roles = signedInModel.Roles.ToString().Split(", ");

            var token = JsonWebToken.Encode(sub, roles);

            return new TokenModel(token);
        }
    }
}
