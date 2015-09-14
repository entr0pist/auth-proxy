angular.module('auth-proxy', []).controller('UserController', function($scope, $http) {
    $scope.whoami = function() {
        $http.get('/api/whoami').success(function(data) {
            if(!data._id) {
                $scope.keygen();
            }

            $scope.user = data;
        }).error(function(data) {

        });
    };

    $scope.keygen = function() {
        $('.keygen').submit();
    };

    $scope.whoami();
});
