angular.module('AdminApp', [ 'ngTagsInput', 'ui.bootstrap' ]).controller('AdminController', function($scope, $http) {
    $scope.tags = {};

    $scope.hostname = window.location.hostname.replace(/\./, '-');

    $scope.parse_groups = function(user) {
        if(!$scope.tags[user.username]) {
            $scope.tags[user.username] = [];
        }

        if(!user.groups || !user.groups[$scope.hostname]) {
            return;
        }

        Object.keys(user.groups[$scope.hostname]).forEach(function(group) {
            $scope.tags[user.username].push(group);
        });
    };

    $http.get('/auth-proxy/admin/api/users').then(function(data) {
        data.data.users.forEach(function(user) {
            $scope.parse_groups(user);
        });

        $scope.users = data.data.users;
        console.log($scope.users);
    }).catch(function(err) {

    });

    $http.get('/auth-proxy/admin/api/policy').then(function(data) {
        $scope.policy = data.data.policy;
    }).catch(function(err) {

    });

    $scope.tag_added = function(username, tag) {
        $http.post('/auth-proxy/admin/api/users/' + username + '/group', { group: tag.text }).then(function(user) {
            $scope.parse_groups(user);
        }).catch(function(err) {

        });
    };

    $scope.tag_removed = function(username, tag) {
        $http.delete('/auth-proxy/admin/api/users/' + username + '/group/' + tag.text).then(function(user) {
            $scope.parse_groups(user);
        }).catch(function(err) {

        });
    };

    $scope.change_policy = function() {
        $http.post('/auth-proxy/admin/api/policy', { policy: $scope.policy }).then(function(policy) {

        }).catch(function(err) {
            
        });
    };
});
